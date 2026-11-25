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
	"net/http"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestValidateDestination(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "https", url: "https://secrets.example.com/v1/secret"},
		{name: "http", url: "http://secrets.example.com:8080/v1/secret"},
		{name: "loopback with port", url: "http://127.0.0.1:8080/hook"},
		{name: "templated path", url: "https://secrets.example.com/{{ .remoteRef.key }}"},
		{name: "dns name with trailing dot", url: "https://secrets.example.com./hook"},
		{name: "unsupported scheme", url: "file:///etc/passwd", wantErr: true},
		{name: "ftp scheme", url: "ftp://example.com/secret", wantErr: true},
		{name: "missing scheme", url: "example.com/secret", wantErr: true},
		{name: "missing host", url: "https:///secret", wantErr: true},
		{name: "empty", url: "", wantErr: true},
		{name: "aws metadata", url: "http://169.254.169.254/latest/meta-data/", wantErr: true},
		{name: "ipv6 metadata", url: "http://[fd00:ec2::254]/latest/meta-data/", wantErr: true},
		{name: "alibaba metadata", url: "http://100.100.100.200/", wantErr: true},
		{name: "link local ipv6", url: "http://[fe80::1]/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDestination(tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateDestination(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDestinationAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		url     string
		wantErr bool
	}{
		{name: "exact host", allowed: []string{"secrets.example.com"}, url: "https://secrets.example.com/v1"},
		{name: "exact host case insensitive", allowed: []string{"secrets.example.com"}, url: "https://SECRETS.example.com/v1"},
		{name: "wildcard subdomain", allowed: []string{"*.example.com"}, url: "https://secrets.example.com/v1"},
		{name: "wildcard does not match apex", allowed: []string{"*.example.com"}, url: "https://example.com/v1", wantErr: true},
		{name: "wildcard does not match suffix only", allowed: []string{"*.example.com"}, url: "https://notexample.com/v1", wantErr: true},
		{name: "host outside allowlist", allowed: []string{"secrets.example.com"}, url: "https://evil.example.org/v1", wantErr: true},
		{name: "any host", allowed: []string{"*"}, url: "https://evil.example.org/v1"},
		{name: "empty allowlist allows any host", allowed: nil, url: "https://evil.example.org/v1"},
		{name: "metadata blocked even when allowlisted", allowed: []string{"*"}, url: "http://169.254.169.254/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := setAllowedHosts(tt.allowed); err != nil {
				t.Fatalf("setAllowedHosts() error = %v", err)
			}
			t.Cleanup(func() {
				if err := setAllowedHosts(nil); err != nil {
					t.Fatalf("reset allowlist: %v", err)
				}
			})

			err := ValidateDestination(tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateDestination(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestRestrictTransportDestinationsBlocksMetadata(t *testing.T) {
	transport := restrictTransportDestinations(&http.Transport{})
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://100.100.100.200/",
	} {
		resp, err := client.Get(target)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatalf("GET %s succeeded, want destination error", target)
		}
		if !errors.Is(err, ErrDestinationNotAllowed) {
			t.Fatalf("GET %s error = %v, want ErrDestinationNotAllowed", target, err)
		}
	}
}

func TestWebhookFeatureAllowedHostsFlag(t *testing.T) {
	restoreAllowedHosts(t)

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "default", want: []string{}},
		{name: "single host", args: []string{"--" + webhookProviderAllowedHostsFlagName, "secrets.example.com"}, want: []string{"secrets.example.com"}},
		{name: "multiple hosts", args: []string{"--" + webhookProviderAllowedHostsFlagName, "a.example.com, *.Example.com."}, want: []string{"a.example.com", "*.example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhookFeature := newWebhookFeature(pflag.ContinueOnError)
			if webhookFeature.Flags.Lookup(webhookProviderAllowedHostsFlagName) == nil {
				t.Fatalf("feature flag %q is not registered", webhookProviderAllowedHostsFlagName)
			}
			if err := webhookFeature.Flags.Parse(tt.args); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			webhookFeature.Initialize()

			got := AllowedHosts()
			if len(got) != len(tt.want) {
				t.Fatalf("AllowedHosts() = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("AllowedHosts() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestWebhookFeatureRejectsInvalidAllowedHosts(t *testing.T) {
	for _, value := range []string{"https://example.com", "user@example.com", "exa mple.com", "a..b,,c", "*example.com", "example.com/path"} {
		webhookFeature := newWebhookFeature(pflag.ContinueOnError)
		err := webhookFeature.Flags.Parse([]string{"--" + webhookProviderAllowedHostsFlagName, value})
		if err == nil {
			t.Errorf("Parse(%q) error = nil, want validation error", value)
		}
	}
}

func restoreAllowedHosts(t *testing.T) {
	t.Helper()
	original := AllowedHosts()
	t.Cleanup(func() {
		allowedHosts.Store(append([]string(nil), original...))
	})
}
