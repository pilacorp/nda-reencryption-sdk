# Umbral Proxy Re-encryption (Go SDK)

Go implementation of the Umbral proxy re-encryption workflow. The package
allows you to:

- Encrypt data for a data owner (Alice) and create a **capsule**.
- Derive a re-encryption key so a proxy can transform the capsule for a delegate
  (Bob).
- Let Bob decrypt the re-encrypted ciphertext using his own secret key.
- Optionally encrypt data streams in fixed-size chunks.

> **Module import:** `github.com/pilacorp/nda-reencryption-sdk`

## Installation

```bash
go get github.com/pilacorp/nda-reencryption-sdk
```

The module exposes packages under `pre`, `utils`, and `curve`. For most use
cases you only need `pre` and `utils`.

## Basic example

The `examples/basic` folder contains a runnable sample:

```go
package main

import (
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

	message := []byte("Proxy re-encryption with Umbral in Go")

	capsule, ciphertext, err := pre.Encrypt(message, alicePK)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	shareDataKey, err := pre.CreateShareDataKey(aliceSK, bobPK, capsule)
	if err != nil {
		log.Fatalf("create share data key: %v", err)
	}

	plaintext, err := pre.Decrypt(bobSK, shareDataKey, ciphertext)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}

	fmt.Printf("Recovered message: %s\n", plaintext)
}
```

Run it with:

```bash
go run ./examples/basic
```

## Streaming support

Package `pre` also exposes `EncryptStream` / `DecryptStream` for large files.
These helpers break data into fixed-size chunks, encrypt each chunk with AES-GCM
using unique nonces, and store chunk metadata inside the capsule. The companion
example `examples/stream/main.go` demonstrates the full flow:

```go
input := bytes.NewReader(bigData)
var cipher bytes.Buffer

chunkSize := uint32(64 * 1024)
capsule, err := pre.EncryptStream(input, &cipher, alicePK, chunkSize)
shareKey, err := pre.CreateShareDataKey(aliceSK, bobPK, capsule)

var plain bytes.Buffer
err = pre.DecryptStream(bytes.NewReader(cipher.Bytes()), &plain, bobSK, shareKey)
```

`chunkSize` defines the frame size used during encryption. Capsule metadata keeps
track of the chunk size so that the decryptor can reconstruct the stream.

## Testing

```bash
go test ./...
```

## License

