package pkcs7

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"
	"time"
)

// newVerifiableSignedData builds a valid SHA256-with-RSA SignedData carrying
// authenticated attributes, parses it back and returns it together with the
// raw DER. It is used as the starting point for the mutation tests below.
func newVerifiableSignedData(t *testing.T, content []byte) (*PKCS7, []byte) {
	t.Helper()
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("failed creating test certificate: %v", err)
	}
	sd, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("failed adding signer: %v", err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatalf("failed finishing signed data: %v", err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatalf("failed parsing signed data: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("baseline verification failed: %v", err)
	}
	return p7, der
}

// makeAttribute builds an authenticated attribute holding the given values in
// its SET OF.
func makeAttribute(t *testing.T, oid asn1.ObjectIdentifier, values ...interface{}) attribute {
	t.Helper()
	set := make([]asn1.RawValue, 0, len(values))
	for _, value := range values {
		encoded, err := asn1.Marshal(value)
		if err != nil {
			t.Fatalf("failed marshalling attribute value: %v", err)
		}
		set = append(set, asn1.RawValue{FullBytes: encoded})
	}
	encodedSet, err := asn1.Marshal(set)
	if err != nil {
		t.Fatalf("failed marshalling attribute set: %v", err)
	}
	var rawSet asn1.RawValue
	if _, err := asn1.Unmarshal(encodedSet, &rawSet); err != nil {
		t.Fatalf("failed decoding attribute set: %v", err)
	}
	return attribute{Type: oid, Value: rawSet}
}

// replaceAuthenticatedAttributes swaps the authenticated attributes of the
// single signer in p7.
func replaceAuthenticatedAttributes(p7 *PKCS7, attrs []attribute) {
	p7.Signers[0].AuthenticatedAttributes = attrs
}

// TestVerifyContentTypeAttributeMatches verifies the happy path where the
// content type authenticated attribute equals the encapsulated content type.
func TestVerifyContentTypeAttributeMatches(t *testing.T) {
	p7, _ := newVerifiableSignedData(t, []byte("content type binding"))

	var contentType asn1.ObjectIdentifier
	if err := unmarshalSingletonAttribute(p7.Signers[0].AuthenticatedAttributes, OIDAttributeContentType, &contentType); err != nil {
		t.Fatalf("failed reading content type attribute: %v", err)
	}
	if !contentType.Equal(OIDData) {
		t.Fatalf("expected content type attribute %q, got %q", OIDData, contentType)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("verification of a well-formed message failed: %v", err)
	}
}

// TestVerifyRejectsMismatchedContentType ensures a content type attribute
// claiming a different OID than the encapsulated content is rejected instead
// of being ignored.
func TestVerifyRejectsMismatchedContentType(t *testing.T) {
	p7, _ := newVerifiableSignedData(t, []byte("content type binding"))
	signer := p7.Signers[0]

	attrs := make([]attribute, 0, len(signer.AuthenticatedAttributes))
	for _, attr := range signer.AuthenticatedAttributes {
		if attr.Type.Equal(OIDAttributeContentType) {
			// OIDSignedData (1.2.840.113549.1.7.2) != OIDData (1.2.840.113549.1.7.1)
			attrs = append(attrs, makeAttribute(t, OIDAttributeContentType, OIDSignedData))
			continue
		}
		attrs = append(attrs, attr)
	}
	replaceAuthenticatedAttributes(p7, attrs)

	err := p7.Verify()
	if err == nil {
		t.Fatal("expected verification to fail for a mismatched content type attribute, but it passed")
	}
	var mismatch *ContentTypeMismatchError
	if !asError(err, &mismatch) {
		t.Fatalf("expected *ContentTypeMismatchError, got %T: %v", err, err)
	}
	if !mismatch.Expected.Equal(OIDData) || !mismatch.Actual.Equal(OIDSignedData) {
		t.Fatalf("unexpected content types in error: expected=%q actual=%q", mismatch.Expected, mismatch.Actual)
	}
}

// TestVerifyRejectsMissingContentType ensures the content type attribute is
// mandatory whenever authenticated attributes are present.
func TestVerifyRejectsMissingContentType(t *testing.T) {
	p7, _ := newVerifiableSignedData(t, []byte("content type binding"))
	signer := p7.Signers[0]

	attrs := make([]attribute, 0, len(signer.AuthenticatedAttributes))
	for _, attr := range signer.AuthenticatedAttributes {
		if attr.Type.Equal(OIDAttributeContentType) {
			continue
		}
		attrs = append(attrs, attr)
	}
	replaceAuthenticatedAttributes(p7, attrs)

	if err := expectInvalidAttribute(p7.Verify(), OIDAttributeContentType, invalidAttributeReasonMissing); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyRejectsDuplicateContentType ensures two content type attributes
// cannot be used to present one value to the verifier and another to a
// lenient consumer.
func TestVerifyRejectsDuplicateContentType(t *testing.T) {
	p7, _ := newVerifiableSignedData(t, []byte("content type binding"))
	signer := p7.Signers[0]

	var attrs []attribute
	inserted := false
	for _, attr := range signer.AuthenticatedAttributes {
		attrs = append(attrs, attr)
		if attr.Type.Equal(OIDAttributeContentType) {
			// duplicate the well-formed content type attribute
			attrs = append(attrs, makeAttribute(t, OIDAttributeContentType, OIDData))
			inserted = true
		}
	}
	if !inserted {
		t.Fatal("test message did not contain a content type attribute")
	}
	replaceAuthenticatedAttributes(p7, attrs)

	if err := expectInvalidAttribute(p7.Verify(), OIDAttributeContentType, invalidAttributeReasonDuplicate); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyRejectsMultiValuedContentType ensures a content type attribute
// whose SET OF holds more than one value is rejected.
func TestVerifyRejectsMultiValuedContentType(t *testing.T) {
	p7, _ := newVerifiableSignedData(t, []byte("content type binding"))
	signer := p7.Signers[0]

	attrs := make([]attribute, 0, len(signer.AuthenticatedAttributes))
	for _, attr := range signer.AuthenticatedAttributes {
		if attr.Type.Equal(OIDAttributeContentType) {
			attrs = append(attrs, makeAttribute(t, OIDAttributeContentType, OIDData, OIDSignedData))
			continue
		}
		attrs = append(attrs, attr)
	}
	replaceAuthenticatedAttributes(p7, attrs)

	if err := expectInvalidAttribute(p7.Verify(), OIDAttributeContentType, invalidAttributeReasonMultiValue); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyRejectsDuplicateAndMultiValuedMessageDigest exercises the same
// singleton rules for the message digest attribute, which protects the
// content hash against value confusion.
func TestVerifyRejectsDuplicateAndMultiValuedMessageDigest(t *testing.T) {
	p7, _ := newVerifiableSignedData(t, []byte("content type binding"))
	signer := p7.Signers[0]

	digest := make([]byte, 32)
	copy(digest, []byte("a"))

	duplicate := make([]attribute, 0, len(signer.AuthenticatedAttributes)+1)
	multiValued := make([]attribute, 0, len(signer.AuthenticatedAttributes))
	for _, attr := range signer.AuthenticatedAttributes {
		switch {
		case attr.Type.Equal(OIDAttributeMessageDigest):
			good := makeAttribute(t, OIDAttributeMessageDigest, digest)
			duplicate = append(duplicate, good, good)
			multiValued = append(multiValued, makeAttribute(t, OIDAttributeMessageDigest, digest, digest))
		default:
			duplicate = append(duplicate, attr)
			multiValued = append(multiValued, attr)
		}
	}

	replaceAuthenticatedAttributes(p7, duplicate)
	if err := expectInvalidAttribute(p7.Verify(), OIDAttributeMessageDigest, invalidAttributeReasonDuplicate); err != nil {
		t.Fatal(err)
	}

	replaceAuthenticatedAttributes(p7, multiValued)
	if err := expectInvalidAttribute(p7.Verify(), OIDAttributeMessageDigest, invalidAttributeReasonMultiValue); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyRejectsDuplicateAndMultiValuedSigningTime exercises the singleton
// rules for the optional signing time attribute.
func TestVerifyRejectsDuplicateAndMultiValuedSigningTime(t *testing.T) {
	p7, _ := newVerifiableSignedData(t, []byte("content type binding"))
	signer := p7.Signers[0]

	now := time.Now().UTC()

	duplicate := make([]attribute, 0, len(signer.AuthenticatedAttributes)+1)
	multiValued := make([]attribute, 0, len(signer.AuthenticatedAttributes))
	for _, attr := range signer.AuthenticatedAttributes {
		switch {
		case attr.Type.Equal(OIDAttributeSigningTime):
			good := makeAttribute(t, OIDAttributeSigningTime, now)
			duplicate = append(duplicate, good, good)
			multiValued = append(multiValued, makeAttribute(t, OIDAttributeSigningTime, now, now))
		default:
			duplicate = append(duplicate, attr)
			multiValued = append(multiValued, attr)
		}
	}

	replaceAuthenticatedAttributes(p7, duplicate)
	if err := expectInvalidAttribute(p7.Verify(), OIDAttributeSigningTime, invalidAttributeReasonDuplicate); err != nil {
		t.Fatal(err)
	}

	replaceAuthenticatedAttributes(p7, multiValued)
	if err := expectInvalidAttribute(p7.Verify(), OIDAttributeSigningTime, invalidAttributeReasonMultiValue); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyAcceptsMessageWithoutAuthenticatedAttributes makes sure the
// content type and singleton checks are not applied to SignerInfos without
// authenticated attributes, as produced for App Store receipts, Android APKs
// and Azure attestation tokens. Such a message must be built with
// SignWithoutAttr, whose signature covers the content directly.
func TestVerifyAcceptsMessageWithoutAuthenticatedAttributes(t *testing.T) {
	content := []byte("no attributes")
	pair, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("failed creating test certificate: %v", err)
	}
	sd, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := sd.SignWithoutAttr(pair.Certificate, *pair.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("failed signing without attributes: %v", err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatalf("failed finishing signed data: %v", err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatalf("failed parsing signed data: %v", err)
	}
	if len(p7.Signers[0].AuthenticatedAttributes) != 0 {
		t.Fatalf("expected no authenticated attributes, got %d", len(p7.Signers[0].AuthenticatedAttributes))
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("verification of a message without authenticated attributes failed: %v", err)
	}
}

// TestVerifyAlgorithmDowngradeRejected ensures a SignerInfo that advertises a
// strong digest algorithm but pairs it with a weaker hash-bearing signature
// algorithm is rejected instead of being silently verified with the weaker
// hash.
func TestVerifyAlgorithmDowngradeRejected(t *testing.T) {
	p7, _ := newVerifiableSignedData(t, []byte("algorithm downgrade"))

	// Claim SHA256 in the digest field but SHA1 in the signature algorithm.
	// Before the fix this combination was accepted and verified using SHA1.
	p7.Signers[0].DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: OIDDigestAlgorithmSHA256}
	p7.Signers[0].DigestEncryptionAlgorithm = pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmRSASHA1}

	err := p7.Verify()
	if err == nil {
		t.Fatal("expected verification to fail for a SHA256/SHA1 algorithm downgrade, but it passed")
	}
	var combo *AlgorithmCombinationError
	if !asError(err, &combo) {
		t.Fatalf("expected *AlgorithmCombinationError, got %T: %v", err, err)
	}
	if !combo.DigestAlgorithm.Equal(OIDDigestAlgorithmSHA256) ||
		!combo.DigestEncryptionAlgorithm.Equal(OIDEncryptionAlgorithmRSASHA1) {
		t.Fatalf("unexpected algorithms in error: digest=%q encryption=%q",
			combo.DigestAlgorithm, combo.DigestEncryptionAlgorithm)
	}
}

// TestVerifyAlgorithmCombinationAcceptsAllowedPairs documents the legitimate
// algorithm encodings that must continue to verify.
func TestVerifyAlgorithmCombinationAcceptsAllowedPairs(t *testing.T) {
	cases := []struct {
		name       string
		digest     asn1.ObjectIdentifier
		encryption asn1.ObjectIdentifier
	}{
		// Separate digest OID plus hash-bearing RSA signature OID.
		{"sha256 + sha256WithRSA", OIDDigestAlgorithmSHA256, OIDEncryptionAlgorithmRSASHA256},
		{"sha1 + sha1WithRSA", OIDDigestAlgorithmSHA1, OIDEncryptionAlgorithmRSASHA1},
		// Generic rsaEncryption carries no hash: the digest OID is authoritative.
		{"sha256 + rsaEncryption", OIDDigestAlgorithmSHA256, OIDEncryptionAlgorithmRSA},
		{"sha1 + rsaEncryption", OIDDigestAlgorithmSHA1, OIDEncryptionAlgorithmRSA},
		// Combined OID in the digest field plus generic rsaEncryption (Azure style).
		{"sha256WithRSA + rsaEncryption", OIDEncryptionAlgorithmRSASHA256, OIDEncryptionAlgorithmRSA},
		// ECDSA combined OIDs.
		{"sha256 + ecdsa-with-SHA256", OIDDigestAlgorithmSHA256, OIDDigestAlgorithmECDSASHA256},
		{"sha384 + ecdsa-with-SHA384", OIDDigestAlgorithmSHA384, OIDDigestAlgorithmECDSASHA384},
		// Named EC public key OIDs carry no hash of their own.
		{"sha256 + ecPublicKey P-256", OIDDigestAlgorithmSHA256, OIDEncryptionAlgorithmECDSAP256},
		// DSA. Both the base id-dsa and id-dsa-with-sha1 OIDs denote SHA1.
		{"sha1 + dsa", OIDDigestAlgorithmSHA1, OIDDigestAlgorithmDSA},
		{"sha1 + dsa-with-SHA1 OID", OIDDigestAlgorithmSHA1, OIDDigestAlgorithmDSASHA1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyAlgorithmCombination(
				pkix.AlgorithmIdentifier{Algorithm: tc.digest},
				pkix.AlgorithmIdentifier{Algorithm: tc.encryption},
			)
			if err != nil {
				t.Fatalf("allowed combination rejected: %v", err)
			}
		})
	}
}

// TestVerifyAlgorithmCombinationRejectsInconsistentPairs covers the matrix of
// disagreeing hash-bearing OIDs.
func TestVerifyAlgorithmCombinationRejectsInconsistentPairs(t *testing.T) {
	pairs := []struct {
		digest     asn1.ObjectIdentifier
		encryption asn1.ObjectIdentifier
	}{
		{OIDDigestAlgorithmSHA256, OIDEncryptionAlgorithmRSASHA1},
		{OIDDigestAlgorithmSHA256, OIDEncryptionAlgorithmRSASHA512},
		{OIDDigestAlgorithmSHA384, OIDEncryptionAlgorithmRSASHA256},
		{OIDDigestAlgorithmSHA512, OIDEncryptionAlgorithmRSASHA1},
		{OIDDigestAlgorithmSHA256, OIDDigestAlgorithmECDSASHA1},
		{OIDDigestAlgorithmSHA384, OIDDigestAlgorithmECDSASHA512},
		{OIDDigestAlgorithmSHA512, OIDDigestAlgorithmECDSASHA256},
	}
	for i, pair := range pairs {
		err := verifyAlgorithmCombination(
			pkix.AlgorithmIdentifier{Algorithm: pair.digest},
			pkix.AlgorithmIdentifier{Algorithm: pair.encryption},
		)
		if err == nil {
			t.Fatalf("case %d: inconsistent pair digest=%q encryption=%q was accepted",
				i, pair.digest, pair.encryption)
		}
		var combo *AlgorithmCombinationError
		if !asError(err, &combo) {
			t.Fatalf("case %d: expected *AlgorithmCombinationError, got %T: %v", i, err, err)
		}
	}
}

// TestUnmarshalSingletonAttribute covers the attribute parsing helper
// directly, including the malformed SET OF case.
func TestUnmarshalSingletonAttribute(t *testing.T) {
	oid := OIDAttributeContentType

	t.Run("missing", func(t *testing.T) {
		err := unmarshalSingletonAttribute(nil, oid, new(asn1.ObjectIdentifier))
		if err := expectInvalidAttributeReason(err, oid, invalidAttributeReasonMissing); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		attrs := []attribute{
			makeAttribute(t, oid, OIDData),
			makeAttribute(t, oid, OIDData),
		}
		err := unmarshalSingletonAttribute(attrs, oid, new(asn1.ObjectIdentifier))
		if err := expectInvalidAttributeReason(err, oid, invalidAttributeReasonDuplicate); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("multi valued", func(t *testing.T) {
		attrs := []attribute{makeAttribute(t, oid, OIDData, OIDSignedData)}
		err := unmarshalSingletonAttribute(attrs, oid, new(asn1.ObjectIdentifier))
		if err := expectInvalidAttributeReason(err, oid, invalidAttributeReasonMultiValue); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("single value", func(t *testing.T) {
		attrs := []attribute{makeAttribute(t, oid, OIDData)}
		var got asn1.ObjectIdentifier
		if err := unmarshalSingletonAttribute(attrs, oid, &got); err != nil {
			t.Fatalf("single valued attribute rejected: %v", err)
		}
		if !got.Equal(OIDData) {
			t.Fatalf("expected %q, got %q", OIDData, got)
		}
	})
}

// asError reports whether err is of the same concrete pointer type as *target
// and, on success, stores it in target.
func asError(err error, target interface{}) bool {
	switch ptr := target.(type) {
	case **ContentTypeMismatchError:
		var e *ContentTypeMismatchError
		if errors.As(err, &e) {
			*ptr = e
			return true
		}
		return false
	case **AlgorithmCombinationError:
		var e *AlgorithmCombinationError
		if errors.As(err, &e) {
			*ptr = e
			return true
		}
		return false
	case **InvalidAttributeError:
		var e *InvalidAttributeError
		if errors.As(err, &e) {
			*ptr = e
			return true
		}
		return false
	default:
		return false
	}
}

func expectInvalidAttribute(err error, oid asn1.ObjectIdentifier, reason string) error {
	return expectInvalidAttributeReason(err, oid, reason)
}

func expectInvalidAttributeReason(err error, oid asn1.ObjectIdentifier, reason string) error {
	if err == nil {
		return fmt.Errorf("expected *InvalidAttributeError for %q (%s), but verification passed", oid, reason)
	}
	var invalid *InvalidAttributeError
	if !asError(err, &invalid) {
		return fmt.Errorf("expected *InvalidAttributeError for %q (%s), got %T: %v", oid, reason, err, err)
	}
	if !invalid.Type.Equal(oid) || invalid.Reason != reason {
		return fmt.Errorf("expected InvalidAttributeError{type=%q, reason=%q}, got {type=%q, reason=%q}",
			oid, reason, invalid.Type, invalid.Reason)
	}
	return nil
}
