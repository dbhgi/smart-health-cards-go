package issuer

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"encoding/json"
	"github.com/skip2/go-qrcode"
	"gopkg.in/square/go-jose.v2"
	"strconv"
	"time"
)

const (
	MAX_SINGLE_JWS_SIZE = 1195
	MAX_CHUNK_SIZE      = 1191
)

type SmartHealthCard struct {
	IssuerUrl            string                 `json:"iss"`
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
		IssuerUrl:            input.IssuerUrl,
		IssuanceDate:         time.Now().Hour(),
		VerifiableCredential: input.VerifiableCredential,
	}

	jws, err := card.Sign(input.PrivateKey, input.KeyId)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// TODO for a health card containing a larger payload, we would need to split the jws into chunks.
// following the logic from this TCP-provided walkthrough: https://github.com/dvci/health-cards-walkthrough/blob/main/SMART%20Health%20Cards.ipynb
func GenerateQRCode(jws string) error {
	// before generating to a qr code we need to convert each character to a byte
	runes := bytes.Runes([]byte(jws))
	s := "shc:/"
	for _, r := range runes {
		nextRune := strconv.Itoa(int(r - 45))
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
		return nil, err
	}

	cardBytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	// now we also need to compress the payload with DEFLATE algorithm
	deflated, err := deflate(string(cardBytes))
	if err != nil {
		return nil, err
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
