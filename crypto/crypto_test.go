package crypto

import (
    "bytes"
    "testing"
)

func TestEncryptDecrypt(t *testing.T) {
    key := []byte("testkey1234567890")
    plaintext := []byte("Hello, World!")
    
    cipher, err := NewCipher(key)
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

func TestNewCipherInvalidKey(t *testing.T) {
    _, err := NewCipher([]byte("short"))
    if err == nil {
        t.Error("Expected error for short key, got nil")
    }
}
