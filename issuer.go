package issuer

import (
	bytes2 "bytes"
	"crypto/ecdsa"
	"encoding/json"
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

	return signer.Sign(buffer.Bytes())
}
