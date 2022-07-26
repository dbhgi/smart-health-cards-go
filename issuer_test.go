package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"gopkg.in/square/go-jose.v2"
)

func TestIssueCard(t *testing.T) {
	var verifiableCredential map[string]interface{}
	if err := json.Unmarshal([]byte(vc), &verifiableCredential); err != nil {
		t.Fatalf("Failed to unmarshal fhir json: %s", err.Error())
	}

	// generate a fake private/public key pair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %s", err.Error())
	}

	// note that the JWK needs to be served up at the .well-known/jwks.json route of the issuing service
	// since verifiers will check that the public key ID matches the private key id in the jws header.
	rawJwk, err := jwk.FromRaw(key)
	if err != nil {
		t.Fatalf("Failed to generate JWK from the private key: %s", err.Error())
	}

	thumbprint, err := rawJwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to generate thumbprint for JWK: %s", err.Error())
	}

	// the key ID must be a base64url-encoded SHA-256 JWK thumbprint of the key used to sign the JWS.
	keyId := base64.RawURLEncoding.EncodeToString(thumbprint)

	jws, err := IssueCard(IssueCardInput{
		IssuerURL:            "https://smarthealth.cards/examples/issuer",
		PrivateKey:           key,
		VerifiableCredential: verifiableCredential,
		KeyId:                keyId,
	})
	if err != nil {
		t.Fatalf("Failed to issue card: %s", err.Error())
	}

	if jws == "" {
		t.Fatalf("Failed to issue card: unknown error")
	}

	// Test that the JWS can be verified using the generated public key
	card, err := jose.ParseSigned(jws)
	if err != nil {
		t.Fatalf("Failed to parse signed JWS from the issued jws: %s", err.Error())
	}

	if _, err = card.Verify(&key.PublicKey); err != nil {
		t.Fatalf("Failed to verify the card to retrieve its contents: %s", err.Error())
	}

	// we can also test that a different key fails to verify the JWS
	fakeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate fake key: %s", err.Error())
	}

	// we expect this to return an error since it's a fake key
	if _, err = card.Verify(&fakeKey.PublicKey); err == nil {
		t.Fatalf("The card was verified using a fake key. Something is wrong with the card.")
	}

	// Convert the JWS into a QR code
	err = GenerateQRCode(jws)
	if err != nil {
		t.Fatalf("Failed to generate QR code from JWS: %s", err.Error())
	}

	fmt.Printf("Created JWS:\n%s\nGenerated QR code, see file qr.png\n", jws)

	return
}
