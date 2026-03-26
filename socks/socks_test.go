package socks

import (
	"testing"
)

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "IPv4",
			input:    []byte{1, 192, 168, 1, 1, 0x1F, 0x90},
			expected: "192.168.1.1:8080",
		},
		{
			name:     "Domain",
			input:    []byte{3, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1F, 0x90},
			expected: "localhost:8080",
		},
		{
			name:    "Incomplete IPv4",
			input:   []byte{1, 192, 168, 1},
			wantErr: true,
		},
		{
			name:     "IPv6",
			input:    []byte{4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x1F, 0x90},
			expected: "[2001:db8::1]:8080",
		},
		{
			name:    "Too short",
			input:   []byte{1},
			wantErr: true,
		},
		{
			name:    "Invalid type",
			input:   []byte{0xFF, 0, 0, 0, 0, 0, 0},
			wantErr: true,
		},
		{
			name:    "Empty",
			input:   []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := ParseAddress(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for input %v, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if addr != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, addr)
			}
		})
	}
}

func TestParseUDPAddress(t *testing.T) {
	// RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT + DATA
	input := []byte{0x00, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x1F, 0x90, 'h', 'e', 'l', 'l', 'o'}

	addr, payload, err := ParseUDPAddress(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if addr != "192.168.1.1:8080" {
		t.Errorf("Expected 192.168.1.1:8080, got %s", addr)
	}

	expected := "hello"
	if string(payload) != expected {
		t.Errorf("Expected payload %q, got %q", expected, string(payload))
	}
}
