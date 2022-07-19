# SMART Health Cards

---
## About

This package will be used for the issuance of [SMART health cards](https://spec.smarthealth.cards/)

## Progress Report (7.19.2022)
- What's done: 
  - Generating a JWS given a FHIR bundle, private/public key pair, JWK thumbprint for key ID
  - Verifying the JWS using the given public key
  - Generating a scannable QR code from the generated JWS
- What's incomplete:
  - Verifying the JWS with the [smart health card verifier portal](https://demo-portals.smarthealth.cards/VerifierPortal.html). The JWS header "kid" value is invalid. I suspect this has to do with the way the issuer_test is generating the JWK. However, this is not really in scope for the issuer package itself, since the key ID is an input, not an output.
  - Generating QR code for large payloads. The smart health card docs indicate that cards are generally supposed to be very small payloads, however in cases where they exceed a certain threshold, they need to be split into chunks and each chunk would correspond to its own QR code. The walkthrough illustrates how the chunking process works.
  - Organizing the issuer package code such that it can be used easily by other services. Currently the issuer_test code lives alongside the issuer in the same package.

## Local Development

- Run `go mod vendor` to install dependencies
- Run `go test` to run `issuer_test.go`. This test file drives the issuer code by doing the following:
  1. Load up a FHIR bundle from json file
  2. Generate a sample private/public key pair and JWK 
  3. Create a JWS using the loaded FHIR bundle and generated cryptographic values. This JWS is the underlying value that comprises the "card"
  4. Tests that the JWS can be verified using the generated public key. Note that JWS verification is different from Smart Health Card verification.
  5. Tests that no other keys may be used to verify the JWS.
  6. Demonstrates converting the JWS into a QR code and writes the QR image to a local file "qr.png"
