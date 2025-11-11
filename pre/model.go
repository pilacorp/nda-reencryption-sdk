package pre

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"math/big"

	crypt "github.com/ethereum/go-ethereum/crypto"
)

type capsule struct {
	E         *ecdsa.PublicKey
	V         *ecdsa.PublicKey
	S         *big.Int
	ChunkSize uint32
	Version   uint8
}

// IsStreamData checks if the data is encrypted in stream mode.
func (c *capsule) IsStreamData() bool {
	return c.ChunkSize > 0
}

func encodeRekey(r *big.Int, p *ecdsa.PublicKey) ([]byte, error) {
	buf := new(bytes.Buffer)

	// serialize r (big.Int)
	sBytes := r.Bytes()
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(sBytes))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(sBytes); err != nil {
		return nil, err
	}

	// serialize p (public key)
	pX, pY := p.X.Bytes(), p.Y.Bytes()

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(pX))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(pX); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(pY))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(pY); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decodeRekey(data []byte) (*big.Int, *ecdsa.PublicKey, error) {
	rData := bytes.NewReader(data)

	r, err := readBig(rData)
	if err != nil {
		return nil, nil, err
	}

	p := new(ecdsa.PublicKey)
	p.Curve = crypt.S256()

	p.X, err = readBig(rData)
	if err != nil {
		return nil, nil, err
	}

	p.Y, err = readBig(rData)
	if err != nil {
		return nil, nil, err
	}

	return r, p, nil
}

func encodeCapsule(cap *capsule) ([]byte, error) {
	buf := new(bytes.Buffer)

	// serialize E (public key)
	ecX, ecY := cap.E.X.Bytes(), cap.E.Y.Bytes()

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(ecX))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(ecX); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(ecY))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(ecY); err != nil {
		return nil, err
	}

	// serialize V (public key)
	vX, vY := cap.V.X.Bytes(), cap.V.Y.Bytes()

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(vX))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(vX); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(vY))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(vY); err != nil {
		return nil, err
	}

	sBytes := cap.S.Bytes()
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(sBytes))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(sBytes); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, cap.ChunkSize); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, cap.Version); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decodeCapsule(data []byte) (*capsule, error) {
	r := bytes.NewReader(data)
	c := new(capsule)

	c.E = new(ecdsa.PublicKey)
	c.E.Curve = crypt.S256()
	c.V = new(ecdsa.PublicKey)
	c.V.Curve = crypt.S256()

	var err error

	c.E.X, err = readBig(r)
	if err != nil {
		return nil, err
	}

	c.E.Y, err = readBig(r)
	if err != nil {
		return nil, err
	}

	c.V.X, err = readBig(r)
	if err != nil {
		return nil, err
	}

	c.V.Y, err = readBig(r)
	if err != nil {
		return nil, err
	}

	c.S, err = readBig(r)
	if err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.LittleEndian, &c.ChunkSize); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.LittleEndian, &c.Version); err != nil {
		return nil, err
	}

	return c, nil
}

func readBig(r *bytes.Reader) (*big.Int, error) {
	var l uint32

	if err := binary.Read(r, binary.LittleEndian, &l); err != nil {
		return nil, err
	}

	b := make([]byte, l)
	if _, err := r.Read(b); err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}
