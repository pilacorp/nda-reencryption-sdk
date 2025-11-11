package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/pilacorp/nda-reencryption-sdk/pre"
	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

func main() {
	aliceSK, alicePK, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate alice keys: %v", err)
	}
	bobSK, bobPK, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate bob keys: %v", err)
	}

	// Prepare an input stream (here we fake a large file with repeated bytes).
	inputData := bytes.Repeat([]byte("streaming-encryption-"), 1024)
	inputReader := bytes.NewReader(inputData)

	var cipherBuf bytes.Buffer
	chunkSize := uint32(64 * 1024) // 64 KiB frames

	capsule, err := pre.EncryptStream(inputReader, &cipherBuf, alicePK, chunkSize)
	if err != nil {
		log.Fatalf("encrypt stream: %v", err)
	}

	shareDataKey, err := pre.CreateShareDataKey(aliceSK, bobPK, capsule)
	if err != nil {
		log.Fatalf("create share data key: %v", err)
	}

	var plainBuf bytes.Buffer
	if err := pre.DecryptStream(bytes.NewReader(cipherBuf.Bytes()), &plainBuf, bobSK, shareDataKey); err != nil {
		log.Fatalf("decrypt stream: %v", err)
	}

	if !bytes.Equal(inputData, plainBuf.Bytes()) {
		log.Fatal("decrypted stream does not match original data")
	}

	fmt.Printf("Stream decrypt succeeded, recovered %d bytes\n", plainBuf.Len())
}
