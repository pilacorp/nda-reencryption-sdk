package main

import (
	"fmt"
	"log"

	"github.com/pilacorp/nda-reencryption-sdk/pre"
	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

func main() {
	// Generate long–term keys for Alice (data owner) and Bob (delegate).
	aliceSK, alicePK, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate alice keys: %v", err)
	}

	bobSK, bobPK, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate bob keys: %v", err)
	}

	message := []byte("NDA re-encryption with NDA SDK in Go")

	aliceEncryptor, capsule, err := pre.NewEncryptor(utils.PublicKeyToCompressedKey(alicePK), 0)
	if err != nil {
		log.Fatalf("create alice encryptor: %v", err)
	}

	// 1) Alice encrypts for herself. The result is the ciphertext and a capsule.
	ciphertext, err := aliceEncryptor.Encrypt(message)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	// 2) Alice derives a share key for Bob. She can send this shareDataKey to the proxy.
	shareDataKey, err := pre.CreateShareDataKey(utils.PrivateKeyToHexString(aliceSK), utils.PublicKeyToCompressedKey(bobPK), capsule)
	if err != nil {
		log.Fatalf("create share data key: %v", err)
	}

	bobDecryptor, err := pre.NewDecryptor(utils.PrivateKeyToHexString(bobSK), shareDataKey)
	if err != nil {
		log.Fatalf("create bob decryptor: %v", err)
	}

	// 3) Bob uses the share key plus his private key to decrypt.
	plaintext, err := bobDecryptor.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}

	fmt.Printf("Original message : %s\n", message)
	fmt.Printf("Recovered message: %s\n", plaintext)
}
