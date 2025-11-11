package pre

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/pilacorp/nda-reencryption-sdk/curve"
	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

func Encrypt(data []byte, pubKey *ecdsa.PublicKey) ([]byte, []byte, error) {
	capsule, keyBytes, err := generateAESKey(pubKey, 0)
	if err != nil {
		return nil, nil, err
	}

	key := hex.EncodeToString(keyBytes)
	cipherText, err := gmcEncrypt(data, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, nil, err
	}

	capsuleAsBytes, err := encodeCapsule(capsule)
	if err != nil {
		return nil, nil, err
	}

	return capsuleAsBytes, cipherText, nil
}

func CreateShareDataKey(priKey *ecdsa.PrivateKey, pkey *ecdsa.PublicKey, capsule []byte) ([]byte, error) {
	r, p, err := rekeyGenerate(priKey, pkey)
	if err != nil {
		fmt.Println(err)
	}

	decodeCap, err := decodeCapsule(capsule)
	if err != nil {
		return nil, err
	}

	reCap, err := reEncryption(r, decodeCap)
	if err != nil {
		return nil, err
	}

	reCapsuleAsBytes, err := encodeCapsule(reCap)
	if err != nil {
		return nil, err
	}

	return utils.ConcatBytes(reCapsuleAsBytes, curve.PointToBytes(p)), nil
}

func CreateRekey(priKey *ecdsa.PrivateKey, pkey *ecdsa.PublicKey) ([]byte, error) {
	r, p, err := rekeyGenerate(priKey, pkey)
	if err != nil {
		fmt.Println(err)
	}

	return encodeRekey(r, p)
}

func ReEncrypt(cap []byte, rekeyBytes []byte) ([]byte, error) {
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

func Decrypt(priKey *ecdsa.PrivateKey, shareDataKey []byte, cipherText []byte) ([]byte, error) {
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

func DecryptByOwner(aPriKey *ecdsa.PrivateKey, capsuleBytes []byte, cipherText []byte) (plainText []byte, err error) {
	decodeCapsule, err := decodeCapsule(capsuleBytes)
	if err != nil {
		return nil, err
	}

	if decodeCapsule.IsStreamData() {
		return nil, fmt.Errorf("encrypted in stream mode")
	}

	keyBytes, err := decryptAESKeyByOwner(aPriKey, decodeCapsule)
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

func decryptAESKey(bPriKey *ecdsa.PrivateKey, cap *capsule, pubX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	S := curve.PointScalarMul(pubX, bPriKey.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(S)))
	point := curve.PointScalarMul(
		curve.PointScalarAdd(cap.E, cap.V), d)
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}

	return keyBytes, nil
}

func decryptAESKeyByOwner(aPriKey *ecdsa.PrivateKey, cap *capsule) ([]byte, error) {
	point1 := curve.PointScalarAdd(cap.E, cap.V)
	point := curve.PointScalarMul(point1, aPriKey.D)
	return utils.Sha3Hash(curve.PointToBytes(point))
}

func decrypt(bPriKey *ecdsa.PrivateKey, cap *capsule, pubX *ecdsa.PublicKey, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := decryptAESKey(bPriKey, cap, pubX)
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

func rekeyGenerate(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	priX, pubX, err := utils.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}

	point := curve.PointScalarMul(bPubKey, priX.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(point)))

	rk := curve.BigIntMul(aPriKey.D, curve.GetInvert(d))
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
