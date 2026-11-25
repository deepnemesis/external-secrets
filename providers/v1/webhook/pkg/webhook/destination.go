/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrDestinationNotAllowed is returned when a webhook destination fails the
// operator's destination policy.
var ErrDestinationNotAllowed = errors.New("webhook destination not allowed")

func mustCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("invalid blocked webhook destination CIDR %q: %v", cidr, err))
	}
	return network
}

var (
	// blockedDestinationNets are ranges a webhook may never reach. Link-local
	// addresses host the cloud metadata services of every major provider.
	blockedDestinationNets = []*net.IPNet{
		mustCIDR("169.254.0.0/16"), // IPv4 link-local, includes 169.254.169.254
		mustCIDR("fe80::/10"),      // IPv6 link-local
	}

	// blockedDestinationIPs covers metadata endpoints outside the link-local
	// ranges above.
	blockedDestinationIPs = []net.IP{
		net.ParseIP("100.100.100.200"), // Alibaba Cloud
		net.ParseIP("fd00:ec2::254"),   // AWS IMDS over IPv6
	}
)

// ValidateDestination checks a webhook URL against the destination policy: the
// scheme must be http or https, a literal host must not be a link-local or
// cloud metadata address, and the host must match the operator's allowlist when
// one is configured.
//
// A hostname is not resolved here. The dial guard installed by
// restrictTransportDestinations applies the same address checks to the resolved
// address of every connection, which also covers DNS answers and redirects.
func ValidateDestination(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("could not parse webhook url: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("webhook url scheme %q is not supported, must be http or https", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return errors.New("webhook url must contain a host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if err := checkDestinationIP(ip); err != nil {
			return err
		}
	}

	return checkAllowedHost(host)
}

// checkDestinationIP refuses link-local and cloud metadata addresses.
func checkDestinationIP(ip net.IP) error {
	for _, blocked := range blockedDestinationIPs {
		if blocked.Equal(ip) {
			return fmt.Errorf("%w: %s is a cloud metadata endpoint", ErrDestinationNotAllowed, ip)
		}
	}
	for _, network := range blockedDestinationNets {
		if network.Contains(ip) {
			return fmt.Errorf("%w: %s is a link-local address", ErrDestinationNotAllowed, ip)
		}
	}
	return nil
}

// checkAllowedHost enforces the operator-level allowlist. An empty allowlist
// permits any host that is not otherwise blocked.
func checkAllowedHost(host string) error {
	allowed := AllowedHosts()
	if len(allowed) == 0 {
		return nil
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pattern := range allowed {
		if pattern == "*" {
			return nil
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return nil
			}
			continue
		}
		if host == pattern {
			return nil
		}
	}

	return fmt.Errorf("%w: host %q is not allowed by --%s", ErrDestinationNotAllowed, host, webhookProviderAllowedHostsFlagName)
}

// AllowedHosts returns the operator-configured host allowlist. An empty list
// means any host is allowed unless it is a blocked address.
func AllowedHosts() []string {
	allowed, ok := allowedHosts.Load().([]string)
	if !ok {
		return nil
	}
	return allowed
}

// restrictTransportDestinations installs a dialer that refuses connections to
// link-local and cloud metadata addresses. The check runs on the address the
// dialer actually connects to, so a hostname that resolves to a blocked address
// is refused as well.
func restrictTransportDestinations(transport *http.Transport) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrDestinationNotAllowed, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("%w: cannot parse dial address %q", ErrDestinationNotAllowed, address)
			}
			return checkDestinationIP(ip)
		},
	}
	transport.DialContext = dialer.DialContext
	return transport
}
