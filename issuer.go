package issuer

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	jose "gopkg.in/square/go-jose.v2"
	"time"
)

type SmartHealthCard struct {
	IssuerUrl            string                 `json:"iss"`
	IssuanceDate         time.Time              `json:"nbf"`
	VerifiableCredential map[string]interface{} `json:"vc"`
}

type IssueCardInput struct {
	IssuerUrl  string
	PrivateKey *ecdsa.PrivateKey
	FhirBundle map[string]interface{}
}

func IssueCard(input IssueCardInput) (*jose.JSONWebSignature, error) {
	card := SmartHealthCard{
		IssuerUrl:            input.IssuerUrl,
		IssuanceDate:         time.Now(),
		VerifiableCredential: input.FhirBundle,
	}

	jws, err := card.Sign(input.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign card: %s", err.Error())
	}

	// need to use the sign method here - change the return value to a JSONWebSignature
	return jws, nil
}

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

	return signer.Sign(bytes)
}
