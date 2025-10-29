# NDA Re-encryption SDK

A comprehensive Rust implementation of the Umbral threshold proxy re-encryption scheme with Go bindings for secure data sharing and delegation.

## 🚀 Overview

The NDA Re-encryption SDK enables secure data sharing through proxy re-encryption, allowing data owners to delegate decryption rights to recipients without exposing their private keys. This is particularly useful for:

- **Secure Data Sharing**: Share encrypted data with specific recipients
- **Key Delegation**: Grant access without sharing private keys
- **Privacy-Preserving Systems**: Maintain data confidentiality in distributed systems
- **Blockchain Integration**: Works seamlessly with Ethereum keys

## 📦 Components

- **umbral-pre**: Core Rust implementation with high-performance cryptographic operations
- **umbral-pre-cgo**: Go bindings for easy integration with Go applications

## 🛠️ Quick Start with Go

### Installation

```bash
go get github.com/dinhwe2612/umbral/umbral-pre-cgo
```

### Basic Usage Example

```go
package main

import (
    "fmt"
    "log"
    
    umbralprecgo "github.com/dinhwe2612/umbral/umbral-pre-cgo"
)

func main() {
    // 1. Generate Ethereum key pairs
    delegatingPrivateKey, delegatingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
    if err != nil {
        log.Fatal(err)
    }
    
    receivingPrivateKey, receivingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
    if err != nil {
        log.Fatal(err)
    }
    
    // 2. Encrypt data
    plaintext := []byte("Sensitive data to be shared")
    capsuleBytes, ciphertext, err := umbralprecgo.EncrypData(delegatingPublicKey, plaintext)
    if err != nil {
        log.Fatal(err)
    }
    
    // 3. Create rekey for delegation
    kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey)
    if err != nil {
        log.Fatal(err)
    }
    
    // 4. Re-encrypt capsule (typically done by proxy servers)
    cfragBytes, err := umbralprecgo.ReencryptCapsule(
        capsuleBytes,
        kfragBytes,
        delegatingPublicKey, // verifying key
        delegatingPublicKey, // delegating key
        receivingPublicKey,  // receiving key
    )
    if err != nil {
        log.Fatal(err)
    }
    
    // 5. Decrypt with recipient's key
    decrypted, err := umbralprecgo.DecryptReencryptedData(
        receivingPrivateKey,
        delegatingPublicKey,
        capsuleBytes,
        cfragBytes,
        ciphertext,
    )
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

## 🔧 API Reference

### Key Management
```go
// Generate Ethereum-compatible key pairs
privateKey, publicKey, err := umbralprecgo.GenerateEthereumKeyPair()
```

### Encryption
```go
// Encrypt data with public key
capsuleBytes, ciphertext, err := umbralprecgo.EncrypData(publicKey, plaintext)
```

### Rekey Creation
```go
// Create rekey fragments for delegation
kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey)
```

### Re-encryption
```go
// Re-encrypt capsule using key fragments
cfragBytes, err := umbralprecgo.ReencryptCapsule(
    capsuleBytes,
    kfragBytes,
    verifyingPublicKey,
    delegatingPublicKey,
    receivingPublicKey,
)
```

### Decryption
```go
// Decrypt re-encrypted data
decrypted, err := umbralprecgo.DecryptReencryptedData(
    receivingPrivateKey,
    delegatingPublicKey,
    capsuleBytes,
    cfragBytes,
    ciphertext,
)
```

## 🏗️ Architecture

```
Data Owner (Alice)          Proxy Servers (Ursulas)        Recipient (Bob)
     |                              |                           |
     |-- Generate Keys ------------>|                           |
     |-- Encrypt Data ------------->|                           |
     |-- Create Rekey ------------->|                           |
     |                              |-- Re-encrypt Capsule ---->|
     |                              |                           |-- Decrypt Data
```

## 🔐 Cryptographic Concepts

Understanding the key components of proxy re-encryption:

### **Capsule**
A cryptographic object that contains the necessary information to decrypt ciphertext. It's created during encryption and contains:
- **Point U**: A curve point used in the decryption process
- **Point V**: Another curve point for decryption
- **Point E**: Additional cryptographic material
- **Nonce**: Random value ensuring security

### **Key Fragment (kFrag)**
A re-encryption key fragment created by the data owner (Alice) to delegate decryption rights to a recipient (Bob). Contains:
- **Re-encryption key**: Allows transformation of capsules
- **Verification key**: Ensures the fragment's authenticity
- **Nonce**: Prevents replay attacks
- **Signature**: Cryptographic proof of authenticity

### **Capsule Fragment (cFrag)**
The result of re-encrypting a capsule using a key fragment. Created by proxy servers (Ursulas) and contains:
- **Re-encrypted capsule data**: Transformed cryptographic material
- **Proof**: Cryptographic proof that re-encryption was performed correctly
- **Verification key**: Used to verify the fragment's validity

### **Rekey**
A cryptographic transformation key that enables proxy re-encryption. The rekey is:
- **Generated by Alice**: Using her private key and Bob's public key
- **Used by Ursulas**: To transform capsules from Alice's encryption to Bob's encryption
- **Threshold-based**: Can be split into multiple fragments for security
- **One-time use**: Each rekey fragment can only be used once

### **Delegating Key**
The private key of the data owner (Alice) who wants to share encrypted data. Used to:
- **Encrypt original data**: Create the initial capsule and ciphertext
- **Generate rekeys**: Create key fragments for delegation
- **Sign operations**: Provide cryptographic proof of authorization

### **Receiving Key**
The public key of the intended recipient (Bob) who will decrypt the re-encrypted data. Used to:
- **Generate rekeys**: Alice uses this to create delegation fragments
- **Verify fragments**: Ensure re-encryption was done correctly
- **Enable decryption**: Bob uses his corresponding private key to decrypt

### **Verifying Key**
A public key used to verify the authenticity of cryptographic operations. Typically:
- **Same as delegating key**: In most cases, Alice's public key
- **Used for validation**: Ensures capsules and fragments are legitimate
- **Prevents tampering**: Cryptographic proof that operations are authorized

### **Proxy Server (Ursula)**
Semi-trusted servers that perform re-encryption operations. They:
- **Receive capsules**: Get encrypted data from Alice
- **Receive key fragments**: Get rekey fragments from Alice
- **Perform re-encryption**: Transform capsules using key fragments
- **Return capsule fragments**: Send re-encrypted data to Bob
- **Cannot decrypt**: Don't have access to private keys

### **Workflow Summary**
```
1. Alice encrypts data → Creates Capsule + Ciphertext
2. Alice creates kFrag → Delegates to Bob via proxy
3. Proxy re-encrypts → Converts Capsule to cFrag
4. Bob decrypts → Uses cFrag + his private key
```

## 📋 Features

- ✅ **Ethereum Integration**: Works with secp256k1 keys from go-ethereum
- ✅ **Memory Safe**: Automatic memory management with Rust safety guarantees
- ✅ **Thread Safe**: Safe for concurrent use in multi-threaded applications
- ✅ **Cross-Platform**: Linux, macOS, and Windows support
- ✅ **High Performance**: Optimized Rust implementation
- ✅ **Serialization**: Convert cryptographic objects to/from bytes
- ✅ **Validation**: Built-in key and data validation

## 🧪 Testing

```bash
# Run all tests
go test -v ./umbral-pre-cgo

# Run specific test
go test -v -run TestE2EWorkflow ./umbral-pre-cgo

# Run with coverage
go test -v -cover ./umbral-pre-cgo
```

## 📚 Examples

Check out the comprehensive examples in the `umbral-pre-cgo/examples/` directory:

- **Basic Usage**: Complete workflow demonstration
- **Error Handling**: Robust error management patterns
- **Key Validation**: Key verification utilities
- **Multiple Messages**: Batch processing examples

## 🔧 Building from Source

If you need to build the Rust library for your platform:

```bash
# Clone the repository
git clone https://github.com/dinhwe2612/umbral.git
cd umbral

# Build Rust library with C bindings
cd umbral-pre
cargo build --release --features bindings-c

# Copy the library to Go bindings directory
# Linux
cp target/release/libumbral_pre.so ../umbral-pre-cgo/lib/

# macOS
cp target/release/libumbral_pre.dylib ../umbral-pre-cgo/lib/

# Windows
copy target\release\umbral_pre.dll ..\umbral-pre-cgo\lib\
```

## ⚠️ Requirements

- **Go**: 1.21 or higher
- **Rust**: Latest stable version
- **CGO**: Must be enabled (`CGO_ENABLED=1`)
- **Operating System**: Linux, macOS, or Windows

## 📖 Documentation

- [Go Bindings Documentation](umbral-pre-cgo/README.md) - Detailed Go integration guide
- [Umbral Paper](https://github.com/nucypher/umbral-doc) - Original research paper
- [Rust Implementation](https://github.com/nucypher/rust-umbral) - Core Rust library

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the GPL-3.0-only License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links


- [Umbral Research Paper](https://github.com/nucypher/umbral-doc)
