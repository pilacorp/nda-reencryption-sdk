package main

import (
	"fmt"
	"log"

	umbralprecgo "github.com/pilacorp/nda-reencryption-sdk/umbral-pre-cgo"
)

func main() {
	fmt.Println("🚀 Umbral Pre-Go v0.0.1 Basic Usage Example")
	fmt.Println("=================================================")

	// Step 1: Generate Ethereum key pairs
	fmt.Println("\n1. Generating Ethereum key pairs...")

	delegatingPrivateKey, delegatingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
	if err != nil {
		log.Fatal("Failed to generate delegating key pair:", err)
	}
	fmt.Printf("   Delegating private key: %x\n", delegatingPrivateKey)
	fmt.Printf("   Delegating public key: %x\n", delegatingPublicKey)

	receivingPrivateKey, receivingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
	if err != nil {
		log.Fatal("Failed to generate receiving key pair:", err)
	}
	fmt.Printf("   Receiving private key: %x\n", receivingPrivateKey)
	fmt.Printf("   Receiving public key: %x\n", receivingPublicKey)

	// Step 2: Encrypt data
	fmt.Println("\n2. Encrypting data...")
	plaintext := []byte("Hello, Umbral Proxy Re-encryption!")
	fmt.Printf("   Plaintext: %s\n", string(plaintext))

	capsuleBytes, ciphertext, err := umbralprecgo.EncrypData(delegatingPublicKey, plaintext)
	if err != nil {
		log.Fatal("Failed to encrypt data:", err)
	}
	fmt.Printf("   Capsule bytes length: %d\n", len(capsuleBytes))
	fmt.Printf("   Ciphertext length: %d\n", len(ciphertext))

	// Step 3: Create rekey
	fmt.Println("\n3. Creating rekey...")
	kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey)
	if err != nil {
		log.Fatal("Failed to create rekey:", err)
	}
	fmt.Printf("   Key fragment bytes length: %d\n", len(kfragBytes))

	// Step 4: Re-encrypt
	fmt.Println("\n4. Re-encrypting capsule...")
	cfragBytes, err := umbralprecgo.ReencryptCapsule(
		capsuleBytes,
		kfragBytes,
		delegatingPublicKey, // verifying key
		delegatingPublicKey, // delegating key
		receivingPublicKey,  // receiving key
	)
	if err != nil {
		log.Fatal("Failed to re-encrypt capsule:", err)
	}
	fmt.Printf("   Capsule fragment bytes length: %d\n", len(cfragBytes))

	// Step 5: Decrypt
	fmt.Println("\n5. Decrypting re-encrypted data...")
	decrypted, err := umbralprecgo.DecryptReencryptedData(
		receivingPrivateKey,
		delegatingPublicKey,
		capsuleBytes,
		cfragBytes,
		ciphertext,
	)
	if err != nil {
		log.Fatal("Failed to decrypt re-encrypted data:", err)
	}
	fmt.Printf("   Decrypted: %s\n", string(decrypted))

	// Verify decryption
	if string(decrypted) == string(plaintext) {
		fmt.Println("\n✅ SUCCESS: Decryption matches original plaintext!")
	} else {
		fmt.Println("\n❌ FAILURE: Decryption does not match original plaintext!")
	}

	fmt.Println("\n🎉 Umbral Proxy Re-encryption workflow completed successfully!")
}
