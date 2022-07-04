package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"os"
	"testing"
)

func TestIssueCard(t *testing.T) {
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

	fmt.Printf("The public key is: %+v", key.PublicKey)

	// note that the keyId needs to be served up as part of the public key at the .well-known/jwks.json
	// since verifiers will check that the public key ID matches the private key id in the jws header.
	keyId := uuid.NewString()

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

	fmt.Printf("Created JWS:\n%s\n", jws)

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

	return
}
