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
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/spf13/pflag"

	"github.com/external-secrets/external-secrets/runtime/feature"
)

const (
	// DefaultMaxResponseBodySize is the default maximum successful webhook
	// response size in bytes.
	DefaultMaxResponseBodySize             = 10 << 20 // 10 MiB
	webhookProviderMaxResponseSizeFlagName = "webhook-provider-max-response-size"
	webhookProviderAllowedHostsFlagName    = "webhook-provider-allowed-hosts"
)

var (
	maxResponseBodySize atomic.Int64
	// allowedHosts holds []string. An empty list allows any destination that is
	// not otherwise blocked.
	allowedHosts atomic.Value
)

type responseBodySizeValue struct {
	value *int64
}

func (v *responseBodySizeValue) Set(rawValue string) error {
	size, err := strconv.ParseInt(rawValue, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid webhook provider maximum response size %q: %w", rawValue, err)
	}
	if err := validateMaxResponseBodySize(size); err != nil {
		return err
	}
	*v.value = size
	return nil
}

func (v *responseBodySizeValue) String() string {
	if v == nil || v.value == nil {
		return ""
	}
	return strconv.FormatInt(*v.value, 10)
}

func (v *responseBodySizeValue) Type() string {
	return "bytes"
}

type allowedHostsValue struct {
	value *[]string
}

func (v *allowedHostsValue) Set(rawValue string) error {
	hosts, err := parseAllowedHosts(rawValue)
	if err != nil {
		return err
	}
	*v.value = hosts
	return nil
}

func (v *allowedHostsValue) String() string {
	if v == nil || v.value == nil {
		return ""
	}
	return strings.Join(*v.value, ",")
}

func (v *allowedHostsValue) Type() string {
	return "strings"
}

// parseAllowedHosts parses the comma separated --webhook-provider-allowed-hosts
// value into lower-case host patterns. An empty value yields an empty list,
// which allows any destination that is not otherwise blocked.
func parseAllowedHosts(rawValue string) ([]string, error) {
	if strings.TrimSpace(rawValue) == "" {
		return []string{}, nil
	}

	entries := strings.Split(rawValue, ",")
	hosts := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(entry), "."))
		if entry == "" {
			return nil, fmt.Errorf("invalid empty host pattern in --%s", webhookProviderAllowedHostsFlagName)
		}
		if strings.ContainsAny(entry, "/@ :") {
			return nil, fmt.Errorf("invalid host pattern %q in --%s: use a bare hostname or *.example.com", entry, webhookProviderAllowedHostsFlagName)
		}
		if strings.Contains(entry, "*") && entry != "*" && !strings.HasPrefix(entry, "*.") {
			return nil, fmt.Errorf("invalid host pattern %q in --%s: a wildcard is only allowed as * or a leading *.", entry, webhookProviderAllowedHostsFlagName)
		}
		hosts = append(hosts, entry)
	}
	return hosts, nil
}

// setAllowedHosts replaces the destination allowlist. It exists for tests and
// for callers that configure the feature without pflag.
func setAllowedHosts(patterns []string) error {
	hosts, err := parseAllowedHosts(strings.Join(patterns, ","))
	if err != nil {
		return err
	}
	allowedHosts.Store(hosts)
	return nil
}

func newWebhookFeature(errorHandling pflag.ErrorHandling) feature.Feature {
	configuredMaxResponseBodySize := int64(DefaultMaxResponseBodySize)
	configuredAllowedHosts := []string{}
	flags := pflag.NewFlagSet("webhook", errorHandling)
	flags.Var(
		&responseBodySizeValue{value: &configuredMaxResponseBodySize},
		webhookProviderMaxResponseSizeFlagName,
		"Maximum successful webhook provider or generator response body size in bytes.",
	)
	flags.Var(
		&allowedHostsValue{value: &configuredAllowedHosts},
		webhookProviderAllowedHostsFlagName,
		"Comma separated host patterns a webhook provider or generator may call, e.g. secrets.example.com,*.example.com. Empty allows any host except link-local and cloud metadata addresses.",
	)

	return feature.Feature{
		Flags: flags,
		Initialize: func() {
			maxResponseBodySize.Store(configuredMaxResponseBodySize)
			allowedHosts.Store(append([]string(nil), configuredAllowedHosts...))
		},
	}
}

func validateMaxResponseBodySize(size int64) error {
	if size <= 0 || size == math.MaxInt64 {
		return fmt.Errorf("webhook provider maximum response size must be between 1 and %d bytes", int64(math.MaxInt64-1))
	}
	return nil
}

func setMaxResponseBodySize(size int64) error {
	if err := validateMaxResponseBodySize(size); err != nil {
		return err
	}
	maxResponseBodySize.Store(size)
	return nil
}

func init() {
	maxResponseBodySize.Store(DefaultMaxResponseBodySize)
	allowedHosts.Store([]string{})
	feature.Register(newWebhookFeature(pflag.ExitOnError))
}
