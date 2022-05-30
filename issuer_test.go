package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

	card, err := IssueCard(IssueCardInput{
		IssuerUrl:            "https://smarthealth.cards/examples/issuer",
		PrivateKey:           key,
		VerifiableCredential: verifiableCredential,
	})
	if err != nil {
		t.Fatalf("Failed to issue card: %s", err.Error())
	}

	if card == nil {
		t.Fatalf("Failed to issue card: unknown error")
	}
	jws, err := card.CompactSerialize()
	if err != nil {
		t.Fatalf("Failed to serialize the jws: %s", err.Error())
	}
	fmt.Printf("issued card: %s", jws)

	result, err := card.Verify(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to verify the card to retrieve its contents: %s", err.Error())
	}
	fmt.Printf("verified card - this would still need to be inflated using flate library: %s", result)

	// we can also test that a different key fails to verify
	fakeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate fake key: %s", err.Error())
	}

	// we expect this to return an error since it's a fake key
	if _, err = card.Verify(&fakeKey.PublicKey); err == nil {
		t.Fatalf("The card was verified using a fake key. Something is wrong with the card.")
	}

	return
}
