package issuer

import (
	bytes2 "bytes"
	"compress/flate"
	"crypto/ecdsa"
	"encoding/json"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
	"time"
)

type SmartHealthCard struct {
	IssuerUrl            string                 `json:"iss"`
	IssuanceDate         int                    `json:"nbf"`
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
		IssuanceDate:         time.Now().Hour(),
		VerifiableCredential: input.VerifiableCredential,
	}

	return card.Sign(input.PrivateKey)
}

// Sign creates the signed jws, storing its serialized value onto the SmartHealthCard struct
func (s SmartHealthCard) Sign(key *ecdsa.PrivateKey) (*jose.JSONWebSignature, error) {
	options := jose.SignerOptions{
		NonceSource: nil,
		EmbedJWK:    true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"zip": "DEF",
			"alg": "ES256",
			"kid": uuid.New(),
		},
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &options)
	if err != nil {
		return nil, err
	}

	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	// now we also need to compress the payload with DEFLATE algorithm
	deflated, err := deflate(string(bytes))
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
	_, err = w.Write([]byte(inflated))
	if err != nil {
		return nil, err
	}
	w.Close()
	return b.Bytes(), nil
}
