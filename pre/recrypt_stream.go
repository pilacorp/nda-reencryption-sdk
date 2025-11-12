package pre

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/pilacorp/nda-reencryption-sdk/curve"
	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

// EncryptStream encrypts the stream data using the owner public key and returns the capsule bytes.
// pubKey is the compressed public key of the owner.
func EncryptStream(inputReader io.Reader, outputWriter io.Writer, pubKey string, chunkSize uint32) error {
	// 1. generate aes key
	pKey, err := utils.PublicCompressedKeyToKey(pubKey)
	if err != nil {
		return err
	}

	capsule, keyBytes, err := generateAESKey(pKey, chunkSize)
	if err != nil {
		return err
	}

	capsuleBytes, err := encodeCapsule(capsule)
	if err != nil {
		return err
	}

	// write the capsule bytes to the output writer.
	_, err = outputWriter.Write(capsuleBytes)
	if err != nil {
		return err
	}

	var (
		key       = hex.EncodeToString(keyBytes)
		aesKey    = key[:32]
		baseNonce = keyBytes[:8]
		nonceIdx  = 0
	)

	// 2. encrypt the stream
	for {
		// generate nonce for each chunk to avoid attack by same nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, chunkSize)

		n, err := io.ReadFull(inputReader, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if errors.Is(err, io.EOF) {
				break
			}

			return err
		}

		// if the last chunk is less than chunk size, set the chunk size final to the actual size.
		if errors.Is(err, io.ErrUnexpectedEOF) || n < int(chunkSize) {
			buf = buf[:n]
		}

		cipherText, err := gmcEncrypt(buf, aesKey, nonceChunkBytes, nil)
		if err != nil {
			return err
		}

		_, err = outputWriter.Write(cipherText)
		if err != nil {
			return err
		}
	}

	// 3. return the capsule
	return nil
}

// DecryptStream decrypts the stream data using the receiver private key and the share data key and returns the plain text.
// inputReader ignore 185 bytes of capsule bytes.
func DecryptStream(inputReader io.Reader, outputWriter io.Writer, recieverPrvKey string, shareDataKey []byte) error {
	// 1. decrypt share data key to get aes key.
	prvKey, err := utils.PrivateKeyStrToKey(recieverPrvKey)
	if err != nil {
		return err
	}

	if len(shareDataKey) != 250 {
		return fmt.Errorf("invalid share data key")
	}

	cap, err := decodeCapsule(shareDataKey[:185])
	if err != nil {
		return err
	}

	pubX, err := curve.BytesToPublicKey(shareDataKey[185:])
	if err != nil {
		return err
	}

	// if the data is not encrypted in stream mode, return an error.
	if !cap.IsStreamData() {
		return fmt.Errorf("encrypted in single mode")
	}

	keyBytes, err := decryptAESKey(prvKey, cap, pubX)
	if err != nil {
		return err
	}

	var (
		key       = hex.EncodeToString(keyBytes)
		aesKey    = key[:32]
		baseNonce = keyBytes[:8]
		nonceIdx  = 0
	)

	// 2. decrypt the stream
	for {
		// generate nonce for each chunk to avoid attack by same nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, cap.ChunkSize+16)
		n, err := io.ReadFull(inputReader, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if err == io.EOF {
				break
			}

			return err
		}

		// if the last chunk is less than chunk size, set the chunk size final to the actual size.
		if errors.Is(err, io.ErrUnexpectedEOF) || n < int(cap.ChunkSize+16) {
			buf = buf[:n]
		}

		plainTextChunk, err := gcmDecrypt(buf, aesKey, nonceChunkBytes, nil)
		if err != nil {
			return err
		}

		_, err = outputWriter.Write(plainTextChunk)
		if err != nil {
			return err
		}
	}

	return nil
}

// DecryptStreamByOwner decrypts the stream data using the owner private key and the original capsule and returns the plain text.
// inputReader ignore 185 bytes of capsule bytes.
func DecryptStreamByOwner(inputReader io.Reader, outputWriter io.Writer, ownerPrvKey string, capsule []byte) error {
	// 1. decrypt original capsule to get aes key.
	prvKey, err := utils.PrivateKeyStrToKey(ownerPrvKey)
	if err != nil {
		return err
	}

	if len(capsule) != 185 {
		return fmt.Errorf("invalid original capsule")
	}

	cap, err := decodeCapsule(capsule)
	if err != nil {
		return err
	}

	// if the data is not encrypted in stream mode, return an error.
	if !cap.IsStreamData() {
		return fmt.Errorf("encrypted in single mode")
	}

	keyBytes, err := decryptAESKeyByOwner(prvKey, cap)
	if err != nil {
		return err
	}

	var (
		key       = hex.EncodeToString(keyBytes)
		aesKey    = key[:32]
		baseNonce = keyBytes[:8]
		nonceIdx  = 0
	)

	// 2. decrypt the stream
	for {
		// generate nonce for each chunk to avoid attack by same nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, cap.ChunkSize+16)
		n, err := io.ReadFull(inputReader, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if err == io.EOF {
				break
			}

			return err
		}

		// if the last chunk is less than chunk size, set the chunk size final to the actual size.
		if errors.Is(err, io.ErrUnexpectedEOF) || n < int(cap.ChunkSize+16) {
			buf = buf[:n]
		}

		plainTextChunk, err := gcmDecrypt(buf, aesKey, nonceChunkBytes, nil)
		if err != nil {
			return err
		}

		_, err = outputWriter.Write(plainTextChunk)
		if err != nil {
			return err
		}
	}

	return nil
}
