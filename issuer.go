package issuer

import "time"

type SmartHealthCard struct {
	IssuerUrl            string                 `json:"iss"`
	IssuanceDate         time.Time              `json:"nbf"`
	VerifiableCredential map[string]interface{} `json:"vc"`
}

type IssueCardInput struct {
	IssuerUrl  string
	PrivateKey string
	FhirBundle map[string]interface{}
}

func IssueCard(input IssueCardInput) (*SmartHealthCard, error) {
	return nil, nil
}