package crypto

import (
    "crypto/sha256"
    "golang.org/x/crypto/hkdf"
    "io"
)

func DeriveKey(password string, salt []byte, keySize int) ([]byte, error) {
    hash := sha256.New
    info := []byte("lunasocks-key-derivation")
    
    hkdf := hkdf.New(hash, []byte(password), salt, info)
    key := make([]byte, keySize)
    _, err := io.ReadFull(hkdf, key)
    if err != nil {
        return nil, err
    }

    return key, nil
}
