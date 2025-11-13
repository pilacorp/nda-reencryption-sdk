package main

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

func main() {
	prv, pub, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate keys: %v", err)
	}

	pubCompress := utils.PublicKeyToCompressedKey(pub)
	prvHex := utils.PrivateKeyToHexString(prv)
	address := crypto.PubkeyToAddress(*pub).Hex()

	fmt.Println("public key:", pubCompress)
	fmt.Println("private key:", prvHex)
	fmt.Println("address:", address)
}
