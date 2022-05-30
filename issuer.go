package issuer

import (
	bytes2 "bytes"
	"compress/flate"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"time"
)

type SmartHealthCard struct {
	IssuerUrl            string                 `json:"iss"`
	IssuanceDate         time.Time              `json:"nbf"`
	VerifiableCredential map[string]interface{} `json:"vc"`
}

type IssueCardInput struct {
	IssuerUrl            string
	PrivateKey           *ecdsa.PrivateKey
	VerifiableCredential map[string]interface{}
}

func IssueCard(input IssueCardInput) (*jose.JSONWebSignature, error) {
	card := SmartHealthCard{
		IssuerUrl:            input.IssuerUrl,
		IssuanceDate:         time.Now(),
		VerifiableCredential: input.VerifiableCredential,
	}

	return card.Sign(input.PrivateKey)
}

// Sign creates the signed jws, storing its serialized value onto the SmartHealthCard struct
func (s SmartHealthCard) Sign(key *ecdsa.PrivateKey) (*jose.JSONWebSignature, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, nil)
	if err != nil {
		return nil, err
	}

	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	// remove any whitespace from the json
	buffer := bytes2.NewBuffer(bytes)
	err = json.Compact(buffer, bytes)
	if err != nil {
		return nil, err
	}

	fmt.Printf("expanded card without whitespace: %s", buffer.String())

	// now we also need to compress the payload with DEFLATE algorithm
	deflated, err := deflate(buffer.String())
	if err != nil {
		return nil, err
	}

	return signer.Sign(deflated)
}

func deflate(inflated string) ([]byte, error) {
	var b bytes2.Buffer
	w, err := flate.NewWriter(&b, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	_, err = w.Write([]byte(inflated))
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
