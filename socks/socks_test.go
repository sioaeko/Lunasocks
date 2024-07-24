package socks

import (
    "bytes"
    "testing"
)

func TestParseAddress(t *testing.T) {
    tests := []struct {
        input    []byte
        expected string
        err      bool
    }{
        {[]byte{1, 192, 168, 1, 1, 0x1F, 0x90}, "192.168.1.1:8080", false},
        {[]byte{3, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1F, 0x90}, "localhost:8080", false},
        {[]byte{1, 192, 168, 1}, "", true},  // Incomplete input
        {[]byte{4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x1F, 0x90}, "[100:203:405:607:809:a0b:c0d:e0f]:8080", false},
    }

    for _, test := range tests {
        addr, err := ParseAddress(test.input)
        if test.err {
            if err == nil {
                t.Errorf("Expected error for input %v, got nil", test.input)
            }
        } else {
            if err != nil {
                t.Errorf("Unexpected error for input %v: %v", test.input, err)
            }
            if addr != test.expected {
                t.Errorf("For input %v, expected %s, got %s", test.input, test.expected, addr)
            }
        }
    }
}
