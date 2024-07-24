package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "io"

    "golang.org/x/crypto/chacha20poly1305"
)

type AEADCipher struct {
    aead cipher.AEAD
}

func NewAEADCipher(key []byte, method string) (*AEADCipher, error) {
    var aead cipher.AEAD
    var err error

    switch method {
    case "aes-256-gcm":
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        aead, err = cipher.NewGCM(block)
    case "chacha20-poly1305":
        aead, err = chacha20poly1305.New(key)
    default:
        return nil, errors.New("unsupported encryption method")
    }

    if err != nil {
        return nil, err
    }

    return &AEADCipher{aead: aead}, nil
}

func (c *AEADCipher) Encrypt(plaintext []byte) ([]byte, error) {
    nonce := make([]byte, c.aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *AEADCipher) Decrypt(ciphertext []byte) ([]byte, error) {
    if len(ciphertext) < c.aead.NonceSize() {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:c.aead.NonceSize()], ciphertext[c.aead.NonceSize():]
    return c.aead.Open(nil, nonce, ciphertext, nil)
}
