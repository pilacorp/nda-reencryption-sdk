package umbralprecgo

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// EncryptWithEthereumKeys encrypts data using Ethereum public key bytes
func EncrypData(publicKeyBytes []byte, plaintext []byte) ([]byte, []byte, error) {
	// Convert Ethereum public key bytes to Umbral public key
	umbralPK, err := GeneratePublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	defer umbralPK.Free()

	// Encrypt data with Umbral public key
	capsule, ciphertext, err := umbralEncrypt(umbralPK, plaintext)
	if err != nil {
		return nil, nil, err
	}
	defer capsule.Free()

	// Convert capsule to bytes for storage/transmission
	capsuleBytes, err := capsuleToBytes(capsule)
	if err != nil {
		return nil, nil, err
	}

	return capsuleBytes, ciphertext, nil
}

// DecryptDataWithOwner decrypts data using Ethereum private key bytes
func DecryptDataWithOwnerKey(privateKeyBytes []byte, publicKeyBytes []byte, capsuleBytes []byte, ciphertext []byte) ([]byte, error) {
	// Convert Ethereum private key bytes to Umbral secret key
	umbralSK, err := GenerateSecretKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	defer umbralSK.Free()

	// Convert Ethereum public key bytes to Umbral public key
	umbralPK, err := GeneratePublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	defer umbralPK.Free()

	// For now, we'll skip capsule deserialization and use a placeholder
	// In real implementation, you would need to implement CapsuleFromBytes
	return nil, fmt.Errorf("DecryptWithEthereumKeys not fully implemented - needs capsule deserialization")
}

// CreateRekey creates rekey fragments with threshold 1 using Ethereum key bytes
func CreateRekey(
	delegatingPrivateKeyBytes []byte,
	receivingPublicKeyBytes []byte,
) ([]byte, error) {
	// Convert delegating private key to Umbral secret key
	delegatingUmbralSK, err := GenerateSecretKeyFromBytes(delegatingPrivateKeyBytes)
	if err != nil {
		return nil, err
	}
	defer delegatingUmbralSK.Free()

	// Convert receiving public key to Umbral public key
	receivingUmbralPK, err := GeneratePublicKeyFromBytes(receivingPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	defer receivingUmbralPK.Free()

	// Create signer from delegating private key
	signer := NewSigner(delegatingUmbralSK)
	defer signer.Free()

	// Generate key fragments for re-encryption with threshold 1
	threshold := 1
	shares := 1

	vkfrags, err := generateKFrags(
		delegatingUmbralSK, // delegating secret key
		receivingUmbralPK,  // receiving public key
		signer,             // signer
		threshold,          // threshold
		shares,             // total shares
		true,               // sign delegating key
		true,               // sign receiving key
	)
	if err != nil {
		return nil, err
	}

	// Free key fragments
	for _, vkf := range vkfrags {
		defer vkf.Free()
	}

	// Convert verified key fragment to bytes
	// First unverify to get KeyFrag, then convert to bytes
	kfrag := vkfrags[0].unverify()
	defer kfrag.Free()

	kfragBytes, err := keyFragToBytes(kfrag)
	if err != nil {
		return nil, err
	}

	return kfragBytes, nil
}

// ReencryptCapsule performs re-encryption using existing rekey
func ReencryptCapsule(
	capsuleBytes []byte,
	kfragBytes []byte,
	verifyingPublicKeyBytes []byte,
	delegatingPublicKeyBytes []byte,
	receivingPublicKeyBytes []byte,
) ([]byte, error) {
	// Convert capsule bytes back to capsule
	capsule, err := capsuleFromBytes(capsuleBytes)
	if err != nil {
		return nil, err
	}
	defer capsule.Free()

	// Convert kfrag bytes back to KeyFrag
	kfrag, err := keyFragFromBytes(kfragBytes)
	if err != nil {
		return nil, err
	}
	defer kfrag.Free()

	// Convert public keys for verification
	verifyingPK, err := GeneratePublicKeyFromBytes(verifyingPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	defer verifyingPK.Free()

	delegatingPK, err := GeneratePublicKeyFromBytes(delegatingPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	defer delegatingPK.Free()

	receivingPK, err := GeneratePublicKeyFromBytes(receivingPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	defer receivingPK.Free()

	// Verify key fragment
	vkfrag, err := kfrag.verify(verifyingPK, delegatingPK, receivingPK)
	if err != nil {
		return nil, err
	}
	defer vkfrag.Free()

	// Re-encrypt using verified key fragment
	vcfrag, err := reencrypt(capsule, vkfrag)
	if err != nil {
		return nil, err
	}
	defer vcfrag.Free()

	// Convert verified capsule fragment to bytes
	cfragBytes, err := capsuleFragToBytes(vcfrag)
	if err != nil {
		return nil, err
	}

	return cfragBytes, nil
}

// DecryptReencryptedData decrypts re-encrypted data using Ethereum keys
func DecryptReencryptedData(
	receivingPrivateKeyBytes []byte,
	delegatingPublicKeyBytes []byte,
	capsuleBytes []byte,
	cfragBytes []byte,
	ciphertext []byte,
) ([]byte, error) {
	// Convert receiving private key to Umbral secret key
	receivingUmbralSK, err := GenerateSecretKeyFromBytes(receivingPrivateKeyBytes)
	if err != nil {
		return nil, err
	}
	defer receivingUmbralSK.Free()

	// Convert delegating public key to Umbral public key
	delegatingUmbralPK, err := GeneratePublicKeyFromBytes(delegatingPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	defer delegatingUmbralPK.Free()

	// Convert capsule bytes back to capsule
	capsule, err := capsuleFromBytes(capsuleBytes)
	if err != nil {
		return nil, err
	}
	defer capsule.Free()

	// Convert capsule fragment bytes back to verified capsule fragment
	vcfrag, err := capsuleFragFromBytes(cfragBytes)
	if err != nil {
		return nil, err
	}
	defer vcfrag.Free()

	// Decrypt re-encrypted data
	decrypted, err := decryptReencrypted(
		receivingUmbralSK,              // receiving secret key
		delegatingUmbralPK,             // delegating public key
		capsule,                        // original capsule
		[]*VerifiedCapsuleFrag{vcfrag}, // verified capsule fragments
		ciphertext,                     // ciphertext
	)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// GenerateEthereumKeyPair generates a new Ethereum key pair and returns private/public key bytes
func GenerateEthereumKeyPair() ([]byte, []byte, error) {
	// Generate Ethereum private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	// Get private key bytes (32 bytes)
	privateKeyBytes := privateKey.D.Bytes()

	// Get public key bytes (compressed format, 33 bytes)
	publicKeyBytes := crypto.CompressPubkey(&privateKey.PublicKey)

	return privateKeyBytes, publicKeyBytes, nil
}

// GetSeedKey extracts the seed key from a re-encrypted capsule
func GetSeedKey(
	receivingPrivateKeyBytes []byte,
	delegatingPublicKeyBytes []byte,
	capsuleBytes []byte,
	cfragBytes []byte,
) ([]byte, []byte, error) {
	// Convert receiving private key to Umbral secret key
	receivingSK, err := GenerateSecretKeyFromBytes(receivingPrivateKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	defer receivingSK.Free()

	// Convert delegating public key to Umbral public key
	delegatingPK, err := GeneratePublicKeyFromBytes(delegatingPublicKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	defer delegatingPK.Free()

	// Convert capsule bytes back to capsule
	capsule, err := capsuleFromBytes(capsuleBytes)
	if err != nil {
		return nil, nil, err
	}
	defer capsule.Free()

	// Convert capsule fragment bytes back to verified capsule fragment
	vcfrag, err := capsuleFragFromBytes(cfragBytes)
	if err != nil {
		return nil, nil, err
	}
	defer vcfrag.Free()

	// Extract seed key
	seedKey, err := getSeedKeyFromCapsule(
		receivingSK,
		delegatingPK,
		capsule,
		[]*VerifiedCapsuleFrag{vcfrag},
	)
	if err != nil {
		return nil, nil, err
	}

	// Get simple capsule bytes for authenticated data
	capsuleBytesSimple, err := capsuleToBytesSimple(capsule)
	if err != nil {
		return nil, nil, err
	}

	return seedKey, capsuleBytesSimple, nil
}

// CreateSymmetricDecryptor creates a symmetric decryptor from a seed key
func CreateSymmetricDecryptor(seedKeyBytes []byte) (*SymmetricDecryptor, error) {
	return NewSymmetricDecryptor(seedKeyBytes)
}
