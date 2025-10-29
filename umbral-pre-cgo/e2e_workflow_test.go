package umbralprecgo

import (
	"testing"
)

// TestE2EWorkflow tests the complete Umbral workflow using utils.go functions
func TestE2EWorkflow(t *testing.T) {
	// Step 1: Generate Ethereum key pairs
	t.Log("Step 1: Generating Ethereum key pairs...")

	// Delegating party (data owner) keys
	delegatingPrivateKeyBytes, delegatingPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate delegating key pair: %v", err)
	}

	// Receiving party (data consumer) keys
	receivingPrivateKeyBytes, receivingPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiving key pair: %v", err)
	}

	// Step 2: Encrypt data
	t.Log("Step 2: Encrypting data...")
	plaintext := []byte("Hello, Umbral Proxy Re-encryption!")

	capsuleBytes, ciphertext, err := EncryptData(delegatingPublicKeyBytes, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}
	t.Logf("Capsule bytes length: %d", len(capsuleBytes))
	t.Logf("Ciphertext length: %d", len(ciphertext))

	// Step 3: Create rekey (key fragments)
	t.Log("Step 3: Creating rekey...")
	kfragBytes, err := CreateRekey(delegatingPrivateKeyBytes, receivingPublicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create rekey: %v", err)
	}
	t.Logf("Key fragment bytes length: %d", len(kfragBytes))

	// Step 4: Re-encrypt capsule
	t.Log("Step 4: Re-encrypting capsule...")
	cfragBytes, err := ReencryptCapsule(
		capsuleBytes,
		kfragBytes,
		delegatingPublicKeyBytes, // verifying public key (signer's key)
		delegatingPublicKeyBytes, // delegating public key
		receivingPublicKeyBytes,  // receiving public key
	)
	if err != nil {
		t.Fatalf("Failed to re-encrypt capsule: %v", err)
	}
	t.Logf("Capsule fragment bytes length: %d", len(cfragBytes))

	// Step 5: Decrypt re-encrypted data
	t.Log("Step 5: Decrypting re-encrypted data...")
	decrypted, err := DecryptReencryptedData(
		receivingPrivateKeyBytes,
		delegatingPublicKeyBytes,
		capsuleBytes,
		cfragBytes,
		ciphertext,
	)
	if err != nil {
		t.Fatalf("Failed to decrypt re-encrypted data: %v", err)
	}

	// Verify decryption
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed: expected %s, got %s", string(plaintext), string(decrypted))
	} else {
		t.Log("E2E workflow completed successfully!")
	}
}

func TestE2EWorkflowWithValidation(t *testing.T) {
	// Step 1: Generate Ethereum key pairs
	t.Log("Step 1: Generating Ethereum key pairs...")
	delegatingPrivateKeyBytes, delegatingPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate delegating key pair: %v", err)
	}

	receivingPrivateKeyBytes, receivingPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiving key pair: %v", err)
	}

	// Step 2: Encrypt data
	t.Log("Step 2: Encrypting data...")
	plaintext := []byte("Umbral Proxy Re-encryption with validation!")
	capsuleBytes, ciphertext, err := EncryptData(delegatingPublicKeyBytes, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Step 3: Create rekey
	t.Log("Step 3: Creating rekey...")
	kfragBytes, err := CreateRekey(delegatingPrivateKeyBytes, receivingPublicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create rekey: %v", err)
	}

	// Step 4: Re-encrypt
	t.Log("Step 4: Re-encrypting...")
	cfragBytes, err := ReencryptCapsule(
		capsuleBytes,
		kfragBytes,
		delegatingPublicKeyBytes,
		delegatingPublicKeyBytes,
		receivingPublicKeyBytes,
	)
	if err != nil {
		t.Fatalf("Failed to re-encrypt: %v", err)
	}

	// Step 5: Decrypt
	t.Log("Step 5: Decrypting...")
	decrypted, err := DecryptReencryptedData(
		receivingPrivateKeyBytes,
		delegatingPublicKeyBytes,
		capsuleBytes,
		cfragBytes,
		ciphertext,
	)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed: expected %s, got %s", string(plaintext), string(decrypted))
	} else {
		t.Log("E2E workflow with validation completed successfully!")
		t.Log("E2E workflow with validation completed successfully!")
	}
}

// Test2E2WorkflowWithSeedKey tests the complete Umbral workflow using seed key
func Test2E2WorkflowWithSeedKey(t *testing.T) {
	// Step 1: Alice generates Ethereum key pair
	alicePrivateKeyBytes, alicePublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice key pair: %v", err)
	}

	bobPrivateKeyBytes, bobPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob key pair: %v", err)
	}

	// Step 2: Alice encrypts data
	t.Log("Step 2: Alice encrypting data...")
	plaintext := []byte("Umbral Proxy Re-encryption with seed key!")
	capsuleBytes, ciphertext, err := EncryptData(alicePublicKeyBytes, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Step 3: Alice creates rekey for Bob
	t.Log("Step 3: Alice creating rekey for Bob...")
	kfragBytes, err := CreateRekey(alicePrivateKeyBytes, bobPublicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create rekey: %v", err)
	}

	// Step 4: Bob re-encrypts data
	// Step 4: Re-encrypt
	t.Log("Step 4: Re-encrypting...")
	cfragBytes, err := ReencryptCapsule(
		capsuleBytes,
		kfragBytes,
		alicePublicKeyBytes,
		alicePublicKeyBytes,
		bobPublicKeyBytes,
	)
	if err != nil {
		t.Fatalf("Failed to re-encrypt: %v", err)
	}

	// Step 5: Bob decrypts data
	// get the seed key by Bob's private key, Alice's public key, capsule, and cfragBytes
	seedKeyBytes, capsuleBytesSimple, err := GetSeedKey(bobPrivateKeyBytes, alicePublicKeyBytes, capsuleBytes, cfragBytes)
	if err != nil {
		t.Fatalf("Failed to get seed key: %v", err)
	}

	// create symmetric decriptor with seed key
	decryptor, err := CreateSymmetricDecryptor(seedKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create symmetric decryptor: %v", err)
	}
	defer decryptor.Free()

	// decrypt data
	decrypted, err := decryptor.DecryptWithCapsule(ciphertext, capsuleBytesSimple)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed: expected %s, got %s", string(plaintext), string(decrypted))
	} else {
		t.Log("E2E workflow with seed key completed successfully!")
	}
}

// func TestE2EWorkflowOwnerDecryptData tests the complete Umbral workflow using owner decrypt data
func TestE2EWorkflowOwnerDecryptData(t *testing.T) {
	// Step 1: Generate Ethereum key pairs
	t.Log("Step 1: Generating Ethereum key pairs...")
	ownerPrivateKeyBytes, ownerPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate owner key pair: %v", err)
	}

	// Step 2: Encrypt data
	t.Log("Step 2: Encrypting data...")
	plaintext := []byte("Umbral Proxy Re-encryption with owner decrypt data!")
	capsuleBytes, ciphertext, err := EncryptData(ownerPublicKeyBytes, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Step 3: Get seed key by owner
	t.Log("Step 3: Getting seed key by owner...")
	seedKeyBytes, capsuleBytesSimple, err := GetSeedKeyByOwner(ownerPrivateKeyBytes, capsuleBytes)
	if err != nil {
		t.Fatalf("Failed to get seed key by owner: %v", err)
	}

	// Step 4: Create symmetric decryptor with seed key
	t.Log("Step 4: Creating symmetric decryptor with seed key...")
	decryptor, err := CreateSymmetricDecryptor(seedKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create symmetric decryptor: %v", err)
	}
	defer decryptor.Free()

	// Step 5: Decrypt data
	t.Log("Step 5: Decrypting data...")
	decrypted, err := decryptor.DecryptWithCapsule(ciphertext, capsuleBytesSimple)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Verify
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed: expected %s, got %s", string(plaintext), string(decrypted))
	} else {
		t.Log("E2E workflow with owner decrypt data completed successfully!")
	}
}

func TestE2EStreamWorkflow(t *testing.T) {
	// Step 1: Generate Ethereum key pairs
	t.Log("Step 1: Generating Ethereum key pairs...")
	ownerPrivateKeyBytes, ownerPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate owner key pair: %v", err)
	}

	viewerPrivateKeyBytes, viewerPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate viewer key pair: %v", err)
	}

	// Step 2: Create encryptor
	t.Log("Step 2: Creating encryptor...")
	encryptor, err := NewEncryptor(ownerPublicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Step 3: Encrypt data
	t.Log("Step 3: Encrypting data...")
	plaintext := []byte("Umbral Proxy Re-encryption with stream workflow!")
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// get capsule bytes
	capsuleBytes, err := encryptor.GetCapsule()
	if err != nil {
		t.Fatalf("Failed to get capsule bytes: %v", err)
	}

	// Step 4: Create rekey
	t.Log("Step 4: Creating rekey...")
	kfragBytes, err := CreateRekey(ownerPrivateKeyBytes, viewerPublicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create rekey: %v", err)
	}

	// Step 5: Re-encrypt capsule
	t.Log("Step 5: Re-encrypting capsule...")
	cfragBytes, err := ReencryptCapsule(
		capsuleBytes,
		kfragBytes,
		ownerPublicKeyBytes,
		ownerPublicKeyBytes,
		viewerPublicKeyBytes,
	)
	if err != nil {
		t.Fatalf("Failed to re-encrypt capsule: %v", err)
	}

	// Step 6: Viewer get seed key
	t.Log("Step 6: Viewer getting seed key...")
	seedKeyBytes, capsuleBytesSimple, err := GetSeedKey(viewerPrivateKeyBytes, ownerPublicKeyBytes, capsuleBytes, cfragBytes)
	if err != nil {
		t.Fatalf("Failed to get seed key: %v", err)
	}

	// Step 7: Viewer decrypt data
	t.Log("Step 7: Viewer decrypting data...")
	decryptor, err := CreateSymmetricDecryptor(seedKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create symmetric decryptor: %v", err)
	}
	defer decryptor.Free()

	// decrypt data
	decrypted, err := decryptor.DecryptWithCapsule(ciphertext, capsuleBytesSimple)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Verify
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed: expected %s, got %s", string(plaintext), string(decrypted))
	} else {
		t.Log("E2E workflow with stream workflow completed successfully!")
	}
}
