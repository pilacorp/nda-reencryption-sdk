package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"

	"github.com/pilacorp/nda-reencryption-sdk/curve"

	"github.com/ethereum/go-ethereum/crypto"
)

// Generate Private and Public key-pair
func GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// convert string to private key
func PrivateKeyStrToKey(privateKeyStr string) (*ecdsa.PrivateKey, error) {
	priKeyAsBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}

	d := new(big.Int).SetBytes(priKeyAsBytes)
	// compute public key
	x, y := crypto.S256().ScalarBaseMult(priKeyAsBytes)

	pubKey := ecdsa.PublicKey{
		Curve: curve.CURVE, X: x, Y: y,
	}
	key := &ecdsa.PrivateKey{
		D:         d,
		PublicKey: pubKey,
	}

	return key, nil
}

// convert public key string to key
func PublicKeyStrToKey(pubKey string) (*ecdsa.PublicKey, error) {
	pubKeyAsBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(curve.CURVE, pubKeyAsBytes)
	key := &ecdsa.PublicKey{
		Curve: curve.CURVE,
		X:     x,
		Y:     y,
	}
	return key, nil
}
