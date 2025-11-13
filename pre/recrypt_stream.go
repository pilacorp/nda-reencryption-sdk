package pre

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// EncryptStream encrypts the stream data using the owner public key and returns the capsule bytes.
// pubKey is the compressed public key of the owner.
func (enc *Encryptor) EncryptStream(ctx context.Context, in io.Reader, out io.Writer) error {
	if enc.chunkSize == 0 {
		return fmt.Errorf("chunk size is not set")
	}

	// initialize the aes cipher.
	block, err := aes.NewCipher(enc.aesKey[:])
	if err != nil {
		return err
	}

	// initialize the aes gcm cipher.
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var (
		nonceIdx  = 0
		baseNonce = enc.baseNonce[:8]
		// overhead is 16 bytes.
		dst = make([]byte, 0, int(enc.chunkSize)+aesgcm.Overhead())
	)

	// encrypt the stream.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// generate nonce for each chunk to avoid attack by same nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, enc.chunkSize)

		n, err := io.ReadFull(in, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if errors.Is(err, io.EOF) {
				break
			}

			return err
		}

		cipherText := aesgcm.Seal(dst[:0], nonceChunkBytes, buf[:n], nil)

		_, err = out.Write(cipherText)
		if err != nil {
			return err
		}
	}

	return nil
}

// DecryptStream decrypts the stream data using the receiver private key and the share data key and returns the plain text.
// inputReader ignore 185 bytes of capsule bytes.
func (d *Decryptor) DecryptStream(ctx context.Context, in io.Reader, out io.Writer) error {
	if d.chunkSize == 0 {
		return fmt.Errorf("chunk size is not set")
	}

	// initialize the aes cipher.
	block, err := aes.NewCipher(d.aesKey[:])
	if err != nil {
		return err
	}

	// initialize the aes gcm cipher.
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var (
		nonceIdx  = 0
		baseNonce = d.baseNonce[:8]
		// overhead is 16 bytes.
		dst = make([]byte, 0, d.chunkSize)
	)

	// decrypt the stream
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// generate nonce for each chunk to avoid attack by same nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, int(d.chunkSize)+aesgcm.Overhead())
		n, err := io.ReadFull(in, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if err == io.EOF {
				break
			}

			return err
		}

		// if the last chunk is less than chunk size, set the chunk size final to the actual size.
		if errors.Is(err, io.ErrUnexpectedEOF) {
			buf = buf[:n]
		}

		plainText, err := aesgcm.Open(dst[:0], nonceChunkBytes, buf[:n], nil)
		if err != nil {
			return err
		}

		_, err = out.Write(plainText)
		if err != nil {
			return err
		}
	}

	return nil
}

// DecryptStreamByOwner decrypts the stream data using the owner private key and the original capsule and returns the plain text.
// inputReader ignore 185 bytes of capsule bytes.
func (d *Decryptor) DecryptStreamByOwner(ctx context.Context, in io.Reader, out io.Writer) error {
	if d.chunkSize <= 0 {
		return fmt.Errorf("encrypted in single mode")
	}

	// initialize the aes cipher.
	block, err := aes.NewCipher(d.aesKey[:])
	if err != nil {
		return err
	}

	// initialize the aes gcm cipher.
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var (
		nonceIdx  = 0
		baseNonce = d.baseNonce[:8]
		dst       = make([]byte, 0, d.chunkSize)
	)

	// decrypt the stream
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// generate nonce for each chunk to avoid attack by same nonce.
		nonceIdxBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(nonceIdxBuf, uint32(nonceIdx))
		nonceChunkBytes := append(baseNonce[:], nonceIdxBuf...)
		nonceIdx++

		// read the chunk from the reader.
		buf := make([]byte, int(d.chunkSize)+aesgcm.Overhead())
		n, err := io.ReadFull(in, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if err == io.EOF {
				break
			}

			return err
		}

		plainText, err := aesgcm.Open(dst[:0], nonceChunkBytes, buf[:n], nil)
		if err != nil {
			return err
		}

		_, err = out.Write(plainText)
		if err != nil {
			return err
		}
	}

	return nil
}
