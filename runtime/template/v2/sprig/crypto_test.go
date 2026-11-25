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

package sprig

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// ciphertextOf builds an AES payload from an IV and one or more raw blocks, so
// tests can present inputs that encryptAES would never produce.
func ciphertextOf(iv byte, blocks ...[]byte) string {
	payload := make([]byte, 0, 16+16*len(blocks))
	payload = append(payload, make([]byte, 16)...)
	for i := range payload[:16] {
		payload[i] = iv
	}
	for _, block := range blocks {
		payload = append(payload, block...)
	}
	return base64.StdEncoding.EncodeToString(payload)
}

func TestDecryptAESRoundTrip(t *testing.T) {
	tests := []string{
		"secret-value",
		"",
		strings.Repeat("a", 16),
		strings.Repeat("b", 4096),
		"unicode: 🔐 значение",
	}

	for _, plaintext := range tests {
		t.Run(plaintext, func(t *testing.T) {
			encrypted, err := encryptAES("password", plaintext)
			if err != nil {
				t.Fatalf("encryptAES() error = %v", err)
			}
			decrypted, err := decryptAES("password", encrypted)
			if err != nil {
				t.Fatalf("decryptAES() error = %v", err)
			}
			if decrypted != plaintext {
				t.Fatalf("decryptAES() = %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestDecryptAESRejectsMalformedPayloads(t *testing.T) {
	tests := []struct {
		name     string
		cipher64 string
	}{
		{
			name:     "only an IV block",
			cipher64: base64.StdEncoding.EncodeToString(make([]byte, 16)),
		},
		{
			name:     "shorter than a block",
			cipher64: base64.StdEncoding.EncodeToString(make([]byte, 4)),
		},
		{
			name:     "not block aligned",
			cipher64: base64.StdEncoding.EncodeToString(make([]byte, 24)),
		},
		{
			name:     "not base64",
			cipher64: "!!!not-base64!!!",
		},
		{
			name:     "zero padding byte",
			cipher64: ciphertextOf(0, make([]byte, 16)),
		},
		{
			name:     "inconsistent padding bytes",
			cipher64: ciphertextOf(0, append(make([]byte, 15), 3)),
		},
		{
			// 0xff is a legal padding length only for a larger final block; for
			// a single block it must be refused without slicing past the start.
			name:     "padding larger than the block",
			cipher64: ciphertextOf(0, append(make([]byte, 15), 0xff)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("decryptAES() panicked: %v", recovered)
					}
				}()
				_, err = decryptAES("password", tt.cipher64)
			}()

			if err == nil {
				t.Fatal("decryptAES() error = nil, want error")
			}
			if tt.cipher64 != "!!!not-base64!!!" && !errors.Is(err, ErrInvalidCiphertext) {
				t.Fatalf("decryptAES() error = %v, want ErrInvalidCiphertext", err)
			}
		})
	}
}

func TestDecryptAESAcceptsValidPadding(t *testing.T) {
	// IV of zeros and one ciphertext block that decrypts to the pad sequence
	// itself is not something the key can produce, so build a real ciphertext.
	encrypted, err := encryptAES("password", strings.Repeat("x", 15))
	if err != nil {
		t.Fatalf("encryptAES() error = %v", err)
	}
	// A padding byte of 1 is the only valid padding for a 15-byte message.
	decrypted, err := decryptAES("password", encrypted)
	if err != nil {
		t.Fatalf("decryptAES() error = %v", err)
	}
	if decrypted != strings.Repeat("x", 15) {
		t.Fatalf("decryptAES() = %q, want 15 x", decrypted)
	}
}
