package go_eccrypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPublicKey_Equals(t *testing.T) {
	privkey, err := GenerateKey()
	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, privkey.PublicKey.Equals(privkey.PublicKey))
}

func TestSerialization(t *testing.T) {
	// PubKey where y starts with 0000.
	p, _ := hex.DecodeString("04f17021dd606fe48530d467f21211e82810438b932432b4f9d8ae03d899f237020000aff977375ae853bb349dff793442d4fabb7d05a64f02e8c6d2ca53db5df2")
	pubkey, _ := NewPublicKeyFromBytes(p)
	assert.Equal(t, p, pubkey.Bytes(false))
}
