package issuer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestIssueCard(t *testing.T) {
	file, err := os.Open("fhir.json")
	if err != nil {
		t.Fatalf("Failed to open fhir.json: %s", err.Error())
	}
	defer file.Close()

	fhirBytes, err := ioutil.ReadAll(file)
	if err != nil {
		t.Fatalf("Failed to read json into bytes: %s", err.Error())
	}

	var fhirBundle map[string]interface{}
	err = json.Unmarshal(fhirBytes, &fhirBundle)
	if err != nil {
		t.Fatalf("Failed to unmarshal fhir json: %s", err.Error())
	}

	card, err := IssueCard(IssueCardInput{
		IssuerUrl:  "",
		PrivateKey: "",
		FhirBundle: fhirBundle,
	})
	if err != nil {
		t.Fatalf("Failed to issue card: %s", err.Error())
	}

	if card == nil {
		t.Fatalf("Failed to issue card: unknown error")
	}

	// now can test something with the card
	fmt.Printf("Issued card: %+v", *card)
}
