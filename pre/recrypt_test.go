package pre

import (
	"testing"

	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

// TestE2E tests the complete encryption and decryption flow
func TestE2E(t *testing.T) {
	// Generate key pairs for Alice and Bob
	alicePrivKey, alicePubKey, err := utils.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate Alice's keys: %v", err)
	}

	bobPrivKey, bobPubKey, err := utils.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate Bob's keys: %v", err)
	}

	// Test data
	testData := []byte("Hello, World! This is a test message for proxy re-encryption. Hello, World! This is a test message for proxy re-encryption.  Hello, World! This is a test message for proxy re-encryption. ")
	t.Logf("Original data: %s", string(testData))

	// Step 1: Alice encrypts data for herself
	capsule, cipherText, err := Encrypt(testData, alicePubKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	t.Logf("Encryption successful. Capsule size: %d bytes, Cipher text size: %d bytes", len(capsule), len(cipherText))

	// Step 2: Alice creates a re-encryption key for Bob
	shareDataKey, err := CreateShareDataKey(alicePrivKey, bobPubKey, capsule)
	if err != nil {
		t.Fatalf("Failed to create share data key: %v", err)
	}
	t.Logf("Share data key created successfully. Size: %d bytes", len(shareDataKey))

	// Step 3: Bob decrypts the data using the share data key
	decryptedData, err := Decrypt(bobPrivKey, shareDataKey, cipherText)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Step 4: owner decrypts the data using the original capsule
	decryptedOwnerData, err := DecryptByOwner(alicePrivKey, capsule, cipherText)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify the decrypted data matches the original
	if string(decryptedData) != string(testData) {
		t.Errorf("Decrypted data doesn't match original. Expected: %s, Got: %s", string(testData), string(decryptedData))
	} else {
		t.Logf("Decryption successful. Decrypted data: %s", string(decryptedData))
		t.Logf("Decryption successful. Decrypted owner data: %s", string(decryptedOwnerData))
	}
}
