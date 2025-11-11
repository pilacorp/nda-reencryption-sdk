package pre

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/pilacorp/nda-reencryption-sdk/curve"
)

func EncryptStream(reader io.Reader, outputWriter io.Writer, pubKey *ecdsa.PublicKey, chunkSize uint32) ([]byte, error) {
	// 1. generate aes key
	capsule, keyBytes, err := generateAESKey(pubKey, chunkSize)
	if err != nil {
		return nil, err
	}

	var (
		key       = hex.EncodeToString(keyBytes)
		aesKey    = key[:32]
		baseNonce = keyBytes[:8]
		nonceIdx  = 0
	)

	// 2. encrypt the stream
	for {
		// generate nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, chunkSize)

		n, err := io.ReadFull(reader, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, err
		}

		// if the last chunk is less than chunk size, set the chunk size final to the actual size.
		if errors.Is(err, io.ErrUnexpectedEOF) || n < int(chunkSize) {
			buf = buf[:n]
		}

		cipherText, err := gmcEncrypt(buf, aesKey, nonceChunkBytes, nil)
		if err != nil {
			return nil, err
		}

		_, err = outputWriter.Write(cipherText)
		if err != nil {
			return nil, err
		}
	}

	// 3. return the capsule
	return encodeCapsule(capsule)
}

func DecryptStream(reader io.Reader, outputWriter io.Writer, priKey *ecdsa.PrivateKey, shareDataKey []byte) error {
	// 1. decrypt share data key to get aes key.
	if len(shareDataKey) != 250 {
		return fmt.Errorf("invalid share data key")
	}

	decodeCapsule, err := decodeCapsule(shareDataKey[:185])
	if err != nil {
		return err
	}

	pubX, err := curve.BytesToPublicKey(shareDataKey[185:])
	if err != nil {
		return err
	}

	// if the data is not encrypted in stream mode, return an error.
	if !decodeCapsule.IsStreamData() {
		return fmt.Errorf("encrypted in single mode")
	}

	keyBytes, err := decryptAESKey(priKey, decodeCapsule, pubX)
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
		// generate nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, decodeCapsule.ChunkSize+16)
		n, err := io.ReadFull(reader, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if err == io.EOF {
				break
			}

			return err
		}

		// if the last chunk is less than chunk size, set the chunk size final to the actual size.
		if errors.Is(err, io.ErrUnexpectedEOF) || n < int(decodeCapsule.ChunkSize+16) {
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

func DecryptStreamByOwner(reader io.Reader, outputWriter io.Writer, priKey *ecdsa.PrivateKey, originalCapsule []byte) error {
	// 1. decrypt original capsule to get aes key.
	if len(originalCapsule) != 185 {
		return fmt.Errorf("invalid original capsule")
	}

	decodeCapsule, err := decodeCapsule(originalCapsule)
	if err != nil {
		return err
	}

	// if the data is not encrypted in stream mode, return an error.
	if !decodeCapsule.IsStreamData() {
		return fmt.Errorf("encrypted in single mode")
	}

	keyBytes, err := decryptAESKeyByOwner(priKey, decodeCapsule)
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
		// generate nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, decodeCapsule.ChunkSize+16)
		n, err := io.ReadFull(reader, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if err == io.EOF {
				break
			}

			return err
		}

		// if the last chunk is less than chunk size, set the chunk size final to the actual size.
		if errors.Is(err, io.ErrUnexpectedEOF) || n < int(decodeCapsule.ChunkSize+16) {
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
