package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Stable errors returned when encoding, parsing or matching the
// SignerIdentifier and RecipientIdentifier of SignerInfo and
// (KeyTrans)RecipientInfo structures. They can be tested with errors.Is.
var (
	// ErrMissingIdentifier is returned when a SignerInfo or RecipientInfo
	// does not contain a signer or recipient identifier at all.
	ErrMissingIdentifier = errors.New("pkcs7: missing signer or recipient identifier")

	// ErrMalformedIdentifier is returned when a SignerInfo or RecipientInfo
	// identifier cannot be decoded or is invalid.
	ErrMalformedIdentifier = errors.New("pkcs7: malformed signer or recipient identifier")

	// ErrDuplicateIdentifier is returned when more than one distinct
	// certificate matches a signer or recipient identifier, making the
	// identification ambiguous.
	ErrDuplicateIdentifier = errors.New("pkcs7: multiple distinct certificates match signer or recipient identifier")

	// ErrNoCertificateForSigner is returned when no certificate in the
	// PKCS7 certificate set matches the signer identifier.
	ErrNoCertificateForSigner = errors.New("pkcs7: No certificate for signer")

	// ErrNoCertificateForRecipient is returned when no RecipientInfo matches
	// the certificate provided for decryption.
	ErrNoCertificateForRecipient = errors.New("pkcs7: no enveloped recipient for provided certificate")

	// ErrNoSubjectKeyIdentifier is returned when a subject key identifier is
	// required to identify a signer or recipient, but the certificate does
	// not contain one.
	ErrNoSubjectKeyIdentifier = errors.New("pkcs7: certificate has no subject key identifier")
)

// identifierKind enumerates the alternatives of the CMS SignerIdentifier and
// RecipientIdentifier CHOICEs (RFC 5652, sections 5.3 and 6.2.1).
type identifierKind int

const (
	identifierKindIssuerAndSerial identifierKind = iota + 1
	identifierKindSubjectKeyIdentifier
)

// identifier is the decoded form of a CMS SignerIdentifier or
// RecipientIdentifier CHOICE. Exactly one of ias or skid is populated,
// as indicated by kind.
type identifier struct {
	kind identifierKind
	ias  issuerAndSerial
	skid []byte
}

// parseIdentifier decodes a SignerIdentifier or RecipientIdentifier CHOICE.
// The issuerAndSerialNumber alternative is a SEQUENCE; the
// subjectKeyIdentifier alternative is the context-specific primitive tag [0]
// holding the key identifier bytes directly (implicit tagging).
//
// It returns ErrMissingIdentifier when raw is empty and
// ErrMalformedIdentifier when the bytes do not form a valid identifier.
func parseIdentifier(raw asn1.RawValue) (identifier, error) {
	if len(raw.FullBytes) == 0 {
		return identifier{}, ErrMissingIdentifier
	}
	if raw.Class == 0 && raw.Tag == 0 && !raw.IsCompound {
		// A RawValue holding only FullBytes has no decoded header; universal
		// tag 0 is never a valid identifier, so decode it now.
		if _, err := asn1.Unmarshal(raw.FullBytes, &raw); err != nil {
			return identifier{}, fmt.Errorf("%w: %v", ErrMalformedIdentifier, err)
		}
	}
	switch {
	case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence && raw.IsCompound:
		var ias issuerAndSerial
		rest, err := asn1.Unmarshal(raw.FullBytes, &ias)
		if err != nil {
			return identifier{}, fmt.Errorf("%w: invalid issuerAndSerialNumber: %v", ErrMalformedIdentifier, err)
		}
		if len(rest) != 0 {
			return identifier{}, fmt.Errorf("%w: trailing data after issuerAndSerialNumber", ErrMalformedIdentifier)
		}
		if ias.SerialNumber == nil || len(ias.IssuerName.FullBytes) == 0 {
			return identifier{}, fmt.Errorf("%w: issuerAndSerialNumber is incomplete", ErrMalformedIdentifier)
		}
		return identifier{kind: identifierKindIssuerAndSerial, ias: ias}, nil
	case raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound:
		if len(raw.Bytes) == 0 {
			return identifier{}, fmt.Errorf("%w: empty subjectKeyIdentifier", ErrMalformedIdentifier)
		}
		skid := make([]byte, len(raw.Bytes))
		copy(skid, raw.Bytes)
		return identifier{kind: identifierKindSubjectKeyIdentifier, skid: skid}, nil
	default:
		return identifier{}, fmt.Errorf("%w: unexpected identifier (class %d, tag %d, compound %t)",
			ErrMalformedIdentifier, raw.Class, raw.Tag, raw.IsCompound)
	}
}

// marshalIssuerAndSerialIdentifier encodes an issuerAndSerialNumber for use
// as a SignerIdentifier or RecipientIdentifier CHOICE.
func marshalIssuerAndSerialIdentifier(ias issuerAndSerial) (asn1.RawValue, error) {
	der, err := asn1.Marshal(ias)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: der}, nil
}

// marshalSKIDIdentifier encodes a subjectKeyIdentifier for use as a
// SignerIdentifier or RecipientIdentifier CHOICE, using the implicit
// context-specific primitive tag [0].
func marshalSKIDIdentifier(skid []byte) (asn1.RawValue, error) {
	if len(skid) == 0 {
		return asn1.RawValue{}, ErrNoSubjectKeyIdentifier
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: skid}, nil
}

// matches reports whether cert is identified by id. The comparison is strict:
// issuerAndSerialNumber requires an exact match of both the raw issuer name
// and the serial number, and subjectKeyIdentifier requires an exact match of
// the certificate SubjectKeyId extension. A certificate without a
// SubjectKeyId never matches a subjectKeyIdentifier.
func (id identifier) matches(cert *x509.Certificate) bool {
	switch id.kind {
	case identifierKindIssuerAndSerial:
		return isCertMatchForIssuerAndSerial(cert, id.ias)
	case identifierKindSubjectKeyIdentifier:
		return len(cert.SubjectKeyId) != 0 && bytes.Equal(cert.SubjectKeyId, id.skid)
	default:
		return false
	}
}

// selectCertificate returns the single certificate from certs identified by
// id. The same certificate (identical raw bytes) appearing more than once is
// not ambiguous and is returned. If several distinct certificates match, an
// error wrapping ErrDuplicateIdentifier is returned, because picking either
// one could confuse different certificates or keys for the same subject. If
// no certificate matches, (nil, nil) is returned and the caller decides which
// error to report.
func selectCertificate(certs []*x509.Certificate, id identifier) (*x509.Certificate, error) {
	var match *x509.Certificate
	for _, cert := range certs {
		if cert == nil || !id.matches(cert) {
			continue
		}
		if match == nil {
			match = cert
			continue
		}
		if bytes.Equal(match.Raw, cert.Raw) {
			// The same certificate included twice is not ambiguous.
			continue
		}
		return nil, fmt.Errorf("%w: %q and %q", ErrDuplicateIdentifier,
			match.Subject.String(), cert.Subject.String())
	}
	return match, nil
}
