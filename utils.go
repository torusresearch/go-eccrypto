package go_eccrypto

import (
	"crypto/sha256"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

func kdf(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha256.New, secret, nil, nil)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, errors.Wrap(err, "cannot read secret from HKDF reader")
	}

	return key, nil
}

func zeroPad(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}

	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return padded
}
