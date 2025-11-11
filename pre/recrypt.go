package pre

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/pilacorp/nda-reencryption-sdk/curve"
	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

// Encrypt encrypts the data using the owner public key and returns the capsule bytes and cipher text.
// ownerPubKey is the compressed public key of the owner.
func Encrypt(data []byte, ownerPubKey string) (capBytes []byte, cipherText []byte, err error) {
	pubKey, err := utils.PublicCompressedKeyToKey(ownerPubKey)
	if err != nil {
		return
	}

	capsule, keyBytes, err := generateAESKey(pubKey, 0)
	if err != nil {
		return
	}

	key := hex.EncodeToString(keyBytes)
	cipherText, err = gmcEncrypt(data, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, nil, err
	}

	capBytes, err = encodeCapsule(capsule)
	if err != nil {
		return nil, nil, err
	}

	return
}

// CreateShareDataKey creates a share data key from the owner private key and the receiver public key for the receiver.
// share data key used to reciever can direct decrypt data .
// receiverPubKey is the compressed public key of the receiver.
func CreateShareDataKey(ownerPrvKey, recieverPubKey string, capsule []byte) ([]byte, error) {
	prvKey, err := utils.PrivateKeyStrToKey(ownerPrvKey)
	if err != nil {
		return nil, err
	}

	pubKey, err := utils.PublicCompressedKeyToKey(recieverPubKey)
	if err != nil {
		return nil, err
	}

	r, p, err := rekeyGenerate(prvKey, pubKey)
	if err != nil {
		fmt.Println(err)
	}

	cap, err := decodeCapsule(capsule)
	if err != nil {
		return nil, err
	}

	reCap, err := reEncryption(r, cap)
	if err != nil {
		return nil, err
	}

	reCapBytes, err := encodeCapsule(reCap)
	if err != nil {
		return nil, err
	}

	return utils.ConcatBytes(reCapBytes, curve.PointToBytes(p)), nil
}

// Decrypt decrypts the data using the receiver private key and the share data key and returns the plain text.
func Decrypt(recieverPrvKey string, shareDataKey []byte, cipherText []byte) ([]byte, error) {
	priKey, err := utils.PrivateKeyStrToKey(recieverPrvKey)
	if err != nil {
		return nil, err
	}

	if len(shareDataKey) != 250 {
		return nil, fmt.Errorf("invalid share data key")
	}

	decodeCapsule, err := decodeCapsule(shareDataKey[:185])
	if err != nil {
		return nil, err
	}

	if decodeCapsule.IsStreamData() {
		return nil, fmt.Errorf("encrypted in stream mode")
	}

	pubX, err := curve.BytesToPublicKey(shareDataKey[185:])
	if err != nil {
		return nil, err
	}

	decryptData, err := decrypt(priKey, decodeCapsule, pubX, cipherText)
	if err != nil {
		return nil, err
	}

	return decryptData, nil
}

// DecryptByOwner decrypts the data using the owner private key and the original capsule and returns the plain text.
func DecryptByOwner(ownerPrvKey string, capsule []byte, cipherText []byte) (plainText []byte, err error) {
	prvKey, err := utils.PrivateKeyStrToKey(ownerPrvKey)
	if err != nil {
		return nil, err
	}

	cap, err := decodeCapsule(capsule)
	if err != nil {
		return nil, err
	}

	if cap.IsStreamData() {
		return nil, fmt.Errorf("encrypted in stream mode")
	}

	keyBytes, err := decryptAESKeyByOwner(prvKey, cap)
	if err != nil {
		return nil, err
	}

	key := hex.EncodeToString(keyBytes)

	plainText, err = gcmDecrypt(cipherText, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func decryptAESKey(prvKey *ecdsa.PrivateKey, cap *capsule, pointX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	S := curve.PointScalarMul(pointX, prvKey.D)

	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pointX),
				curve.PointToBytes(&prvKey.PublicKey)),
			curve.PointToBytes(S)))

	point := curve.PointScalarMul(
		curve.PointScalarAdd(cap.E, cap.V), d)

	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}

	return keyBytes, nil
}

func decryptAESKeyByOwner(prvKey *ecdsa.PrivateKey, cap *capsule) ([]byte, error) {
	point1 := curve.PointScalarAdd(cap.E, cap.V)
	point := curve.PointScalarMul(point1, prvKey.D)

	return utils.Sha3Hash(curve.PointToBytes(point))
}

func decrypt(prvKey *ecdsa.PrivateKey, cap *capsule, pointX *ecdsa.PublicKey, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := decryptAESKey(prvKey, cap, pointX)
	if err != nil {
		return nil, err
	}

	key := hex.EncodeToString(keyBytes)

	plainText, err = gcmDecrypt(cipherText, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func rekeyGenerate(ownerPrvKey *ecdsa.PrivateKey, recieverPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	priX, pubX, err := utils.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}

	point := curve.PointScalarMul(recieverPubKey, priX.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(recieverPubKey)),
			curve.PointToBytes(point)))

	rk := curve.BigIntMul(ownerPrvKey.D, curve.GetInvert(d))
	rk.Mod(rk, curve.N)

	return rk, pubX, nil
}

func reEncryption(rk *big.Int, cap *capsule) (*capsule, error) {
	x1, y1 := curve.CURVE.ScalarBaseMult(cap.S.Bytes())
	tempX, tempY := curve.CURVE.ScalarMult(cap.E.X, cap.E.Y,
		utils.HashToCurve(
			utils.ConcatBytes(
				curve.PointToBytes(cap.E),
				curve.PointToBytes(cap.V))).Bytes())
	x2, y2 := curve.CURVE.Add(cap.V.X, cap.V.Y, tempX, tempY)

	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		return nil, fmt.Errorf("%s", "Capsule not match")
	}

	newCapsule := &capsule{
		E:         curve.PointScalarMul(cap.E, rk),
		V:         curve.PointScalarMul(cap.V, rk),
		S:         cap.S,
		ChunkSize: cap.ChunkSize,
		Version:   cap.Version,
	}

	return newCapsule, nil
}

func generateAESKey(pubKey *ecdsa.PublicKey, chunkSize uint32) (cap *capsule, keyBytes []byte, err error) {
	s := new(big.Int)
	priE, pubE, err := utils.GenerateKeys()
	priV, pubV, err := utils.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}

	h := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(pubE),
			curve.PointToBytes(pubV)))

	s = curve.BigIntAdd(priV.D, curve.BigIntMul(priE.D, h))
	point := curve.PointScalarMul(pubKey, curve.BigIntAdd(priE.D, priV.D))

	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, nil, err
	}

	cap = &capsule{
		E:         pubE,
		V:         pubV,
		S:         s,
		ChunkSize: chunkSize,
	}

	return cap, keyBytes, nil
}

func createRekey(ownerPrvKey *ecdsa.PrivateKey, recieverPubKey *ecdsa.PublicKey) ([]byte, error) {
	r, p, err := rekeyGenerate(ownerPrvKey, recieverPubKey)
	if err != nil {
		fmt.Println(err)
	}

	return encodeRekey(r, p)
}

func reEncrypt(cap []byte, rekeyBytes []byte) ([]byte, error) {
	r, pubX, err := decodeRekey(rekeyBytes)
	if err != nil {
		return nil, err
	}

	decodeCap, err := decodeCapsule(cap)
	if err != nil {
		fmt.Println("decode error:", err)

		return nil, err
	}

	reCap, err := reEncryption(r, decodeCap)
	if err != nil {
		fmt.Println("re encryption error:", err)

		return nil, err
	}

	reCapsuleAsBytes, err := encodeCapsule(reCap)
	if err != nil {
		fmt.Println("encode error:", err)

		return nil, err
	}

	return utils.ConcatBytes(reCapsuleAsBytes, curve.PointToBytes(pubX)), nil
}
