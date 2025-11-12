package pre

import (
	"bytes"
	"testing"

	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

func TestE2EStream(t *testing.T) {
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

	encryptReader := bytes.NewReader(testData)
	encryptWriter := bytes.NewBuffer(nil)

	// Step 1: Alice encrypts the stream
	err = EncryptStream(encryptReader, encryptWriter, utils.PublicKeyToCompressedKey(alicePubKey), 2)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	capsuleBytes := make([]byte, 185)
	if _, err := encryptWriter.Read(capsuleBytes); err != nil {
		t.Fatalf("read capsule bytes: %v", err)
	}

	// Step 2: Alice creates a re-encryption key for Bob
	shareDataKey, err := CreateShareDataKey(utils.PrivateKeyToHexString(alicePrivKey), utils.PublicKeyToCompressedKey(bobPubKey), capsuleBytes)
	if err != nil {
		t.Fatalf("Failed to create share data key: %v", err)
	}
	t.Logf("Share data key created successfully. Size: %d bytes", len(shareDataKey))

	// Step 3: Bob decrypts the stream
	decryptWriter := bytes.NewBuffer(nil)
	err = DecryptStream(encryptWriter, decryptWriter, utils.PrivateKeyToHexString(bobPrivKey), shareDataKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	t.Logf("Decryption successful. Decrypted data: %s", decryptWriter.String())

	encryptOwnerReader := bytes.NewReader(testData)
	encryptOwnerWriter := bytes.NewBuffer(nil)

	// Step 4: Alice encrypts the stream
	err = EncryptStream(encryptOwnerReader, encryptOwnerWriter, utils.PublicKeyToCompressedKey(alicePubKey), 2)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	capsuleOwnerBytes := make([]byte, 185)
	if _, err := encryptOwnerWriter.Read(capsuleOwnerBytes); err != nil {
		t.Fatalf("read capsule owner bytes: %v", err)
	}

	// Step 5: owner decrypts the stream
	decryptWriterOwner := bytes.NewBuffer(nil)
	err = DecryptStreamByOwner(encryptOwnerWriter, decryptWriterOwner, utils.PrivateKeyToHexString(alicePrivKey), capsuleOwnerBytes)
	if err != nil {
		t.Fatalf("Decryption Owner failed: %v", err)
	}

	t.Logf("Decryption successful. Decrypted owner data: %s", decryptWriterOwner.String())
}
