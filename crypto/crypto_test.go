package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("testkey1234567890testkey12345678") // 32 bytes for AES-256
	plaintext := []byte("Hello, World!")

	cipher, err := NewAEADCipher(key, "aes-256-gcm")
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match original. Got %s, want %s", decrypted, plaintext)
	}
}

func TestNewAEADCipherInvalidKey(t *testing.T) {
	_, err := NewAEADCipher([]byte("short"), "aes-256-gcm")
	if err == nil {
		t.Error("Expected error for short key, got nil")
	}
}

func TestNewCipherFromPassword(t *testing.T) {
	cipher, err := NewCipher([]byte("my-password"))
	if err != nil {
		t.Fatalf("Failed to create cipher from password: %v", err)
	}

	plaintext := []byte("test data for cipher")
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match. Got %s, want %s", decrypted, plaintext)
	}
}

func TestChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, err := NewAEADCipher(key, "chacha20-poly1305")
	if err != nil {
		t.Fatalf("Failed to create ChaCha20 cipher: %v", err)
	}

	plaintext := []byte("ChaCha20 test data")
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match. Got %s, want %s", decrypted, plaintext)
	}
}

func TestUnsupportedMethod(t *testing.T) {
	_, err := NewAEADCipher([]byte("key"), "unsupported-method")
	if err == nil {
		t.Error("Expected error for unsupported method, got nil")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := []byte("testkey1234567890testkey12345678")
	cipher, err := NewAEADCipher(key, "aes-256-gcm")
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	_, err = cipher.Decrypt([]byte("short"))
	if err == nil {
		t.Error("Expected error for short ciphertext, got nil")
	}
}

func TestDeriveKey(t *testing.T) {
	salt := []byte("test-salt")
	key1, err := DeriveKey("password1", salt, 32)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	key2, err := DeriveKey("password2", salt, 32)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("Different passwords should produce different keys")
	}

	if len(key1) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key1))
	}
}
