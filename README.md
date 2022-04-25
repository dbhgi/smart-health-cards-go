# SMART Health Cards

---
## About

This package will be used for the issuance of [SMART health cards](https://spec.smarthealth.cards/)

## Local Development

- Run `go mod vendor` to install dependencies
- Run `go test` to run `issuer_test.go`. This test file will drive the issuer code by doing the following:
  1. Load up a FHIR bundle from json file
  2. Generate a sample private/public key pair (this is where I'm currently stuck)
  3. Test verification of the generated JWS.
