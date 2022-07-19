package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"os"
	"testing"
)

func TestIssueCard(t *testing.T) {
	// verifiable credential may be any JSON payload
	file, err := os.Open("verifiable_credential.json")
	if err != nil {
		t.Fatalf("Failed to open verifiable_credential.json: %s", err.Error())
	}
	defer file.Close()

	vcBytes, err := ioutil.ReadAll(file)
	if err != nil {
		t.Fatalf("Failed to read json into bytes: %s", err.Error())
	}

	var verifiableCredential map[string]interface{}
	err = json.Unmarshal(vcBytes, &verifiableCredential)
	if err != nil {
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
	keyId := base64.URLEncoding.EncodeToString(thumbprint)

	// TODO: the verifier portal is complaining about this keyId, saying it must be a base64url encoded string. I suspect
	// it may have something to do with the way I'm generating the JWK, most example involve fetching the keyset from a third party
	// however this problem is not really in scope for the package since it's a prerequisite to issuing the card.

	jws, err := IssueCard(IssueCardInput{
		IssuerUrl:            "https://smarthealth.cards/examples/issuer",
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

	card, err := jose.ParseSigned(jws)
	if err != nil {
		t.Fatalf("Failed to parse signed JWS from the issued jws: %s", err.Error())
	}

	_, err = card.Verify(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to verify the card to retrieve its contents: %s", err.Error())
	}

	// we can also test that a different key fails to verify
	fakeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate fake key: %s", err.Error())
	}

	// we expect this to return an error since it's a fake key
	if _, err = card.Verify(&fakeKey.PublicKey); err == nil {
		t.Fatalf("The card was verified using a fake key. Something is wrong with the card.")
	}

	err = GenerateQRCode(jws)
	if err != nil {
		t.Fatalf("Failed to generate QR code from JWS: %s", err.Error())
	}

	fmt.Printf("Created JWS:\n%s\nGenerated QR code, see file qr.png\n", jws)

	return
}
