package issuer

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/skip2/go-qrcode"
	"gopkg.in/square/go-jose.v2"
)

const (
	MAX_SINGLE_JWS_SIZE = 1195
	MAX_CHUNK_SIZE      = 1191

	// LOWEST_VALUED_JWS_ORDINAL_VALUE From SMART health card spec: 45 is the ordinal value of -, the lowest-valued character that can appear in a compact JWS.
	// Subtracting 45 from the ordinal values of valid JWS characters produces a range between 00 and 99, ensuring that each character of the JWS can be represented in exactly two base-10 numeric digits.
	LOWEST_VALUED_JWS_ORDINAL_VALUE = 45

	QR_CODE_PREFIX = "shc:/"
)

type SmartHealthCard struct {
	IssuerURL            string                 `json:"iss"`
	IssuanceDate         int                    `json:"nbf"`
	VerifiableCredential map[string]interface{} `json:"vc"`
}

type IssueCardInput struct {
	IssuerUrl            string
	PrivateKey           *ecdsa.PrivateKey
	KeyId                string
	VerifiableCredential map[string]interface{}
}

func IssueCard(input IssueCardInput) (string, error) {
	card := SmartHealthCard{
		IssuerURL:            input.IssuerUrl,
		IssuanceDate:         time.Now().Hour(),
		VerifiableCredential: input.VerifiableCredential,
	}

	jws, err := card.Sign(input.PrivateKey, input.KeyId)
	if err != nil {
		return "", fmt.Errorf("failed to sign jws: %s", err.Error())
	}
	return jws.CompactSerialize()
}

// TODO for a health card containing a larger payload, we would need to split the jws into chunks.
// following the logic from this TCP-provided walkthrough: https://github.com/dvci/health-cards-walkthrough/blob/main/SMART%20Health%20Cards.ipynb
func GenerateQRCode(jws string) error {
	// before generating to a qr code we need to convert each character to a byte
	runes := bytes.Runes([]byte(jws))
	s := QR_CODE_PREFIX
	for _, r := range runes {
		nextRune := strconv.Itoa(int(r - LOWEST_VALUED_JWS_ORDINAL_VALUE))
		if len(nextRune) == 1 {
			nextRune = "0" + nextRune
		}
		s += nextRune
	}
	err := qrcode.WriteFile(s, qrcode.Low, 256, "qr.png")
	if err != nil {
		return err
	}
	return nil
}

// Sign creates the signed jws, storing its serialized value onto the SmartHealthCard struct
func (s SmartHealthCard) Sign(key *ecdsa.PrivateKey, keyId string) (*jose.JSONWebSignature, error) {
	options := jose.SignerOptions{
		NonceSource: nil,
		EmbedJWK:    true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"zip": "DEF",
			"alg": "ES256",
			"kid": keyId,
		},
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create new signer using provided key: %s", err.Error())
	}

	cardBytes, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal card into json: %s", err)
	}

	// now we also need to compress the payload with DEFLATE algorithm
	deflated, err := deflate(string(cardBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to compress card bytes: %s", err)
	}

	return signer.Sign(deflated)
}

func deflate(inflated string) ([]byte, error) {
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	_, err = w.Write([]byte(inflated))
	if err != nil {
		return nil, err
	}
	_ = w.Close()
	return b.Bytes(), nil
}
