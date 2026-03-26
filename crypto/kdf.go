package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func DeriveKey(password string, salt []byte, keySize int) ([]byte, error) {
	hash := sha256.New
	info := []byte("lunasocks-key-derivation")

	r := hkdf.New(hash, []byte(password), salt, info)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}

	return key, nil
}
