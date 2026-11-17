package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// Verify is a wrapper around VerifyWithChain() that initializes an empty
// trust store, effectively disabling certificate verification when validating
// a signature.
func (p7 *PKCS7) Verify() (err error) {
	return p7.VerifyWithChain(nil)
}

// VerifyWithChain checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to one of the roots in the
// truststore. When the PKCS7 object includes the signing time
// authenticated attr verifies the chain at that time and UTC now
// otherwise.
func (p7 *PKCS7) VerifyWithChain(truststore *x509.CertPool) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer, truststore); err != nil {
			return err
		}
	}
	return nil
}

// VerifyWithChainAtTime checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to a root in the truststore at
// currentTime. It does not use the signing time authenticated
// attribute.
func (p7 *PKCS7) VerifyWithChainAtTime(truststore *x509.CertPool, currentTime time.Time) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignatureAtTime(p7, signer, truststore, currentTime); err != nil {
			return err
		}
	}
	return nil
}

// SigningTimeNotValidError is returned when the signing time attribute
// falls outside of the signer certificate validity.
type SigningTimeNotValidError struct {
	SigningTime time.Time
	NotBefore   time.Time // NotBefore of signer
	NotAfter    time.Time // NotAfter of signer
}

func (e *SigningTimeNotValidError) Error() string {
	return fmt.Sprintf("pkcs7: signing time %q is outside of certificate validity %q to %q",
		e.SigningTime.Format(time.RFC3339),
		e.NotBefore.Format(time.RFC3339),
		e.NotAfter.Format(time.RFC3339))
}

// ContentTypeMismatchError is returned when the content type authenticated
// attribute of a SignerInfo does not match the content type of the
// encapsulated content.
type ContentTypeMismatchError struct {
	Expected asn1.ObjectIdentifier
	Actual   asn1.ObjectIdentifier
}

func (e *ContentTypeMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: content type attribute %q does not match encapsulated content type %q",
		e.Actual.String(), e.Expected.String())
}

// InvalidAttributeError is returned when an authenticated attribute is
// malformed: a required attribute is missing, the same attribute type
// occurs more than once, or its value set does not contain exactly one
// value.
type InvalidAttributeError struct {
	Type   asn1.ObjectIdentifier
	Reason string
}

func (e *InvalidAttributeError) Error() string {
	return fmt.Sprintf("pkcs7: invalid authenticated attribute %q: %s", e.Type.String(), e.Reason)
}

// AlgorithmCombinationError is returned when the digest algorithm and the
// digest encryption (signature) algorithm declared by a SignerInfo do not
// resolve to a single, consistent hash. Rejecting such combinations prevents
// a message from silently being verified with a weaker algorithm than the
// one it claims to use.
type AlgorithmCombinationError struct {
	DigestAlgorithm           asn1.ObjectIdentifier
	DigestEncryptionAlgorithm asn1.ObjectIdentifier
}

func (e *AlgorithmCombinationError) Error() string {
	return fmt.Sprintf("pkcs7: inconsistent digest algorithm %q and digest encryption algorithm %q",
		e.DigestAlgorithm.String(), e.DigestEncryptionAlgorithm.String())
}

func verifySignatureAtTime(p7 *PKCS7, signer signerInfo, truststore *x509.CertPool, currentTime time.Time) error {
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return errors.New("pkcs7: No certificate for signer")
	}
	signedData, _, err := verifySignedAttributes(p7, signer, ee)
	if err != nil {
		return err
	}
	if truststore != nil {
		if _, err := verifyCertChain(ee, p7.Certificates, truststore, currentTime); err != nil {
			return err
		}
	}
	sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
}

func verifySignature(p7 *PKCS7, signer signerInfo, truststore *x509.CertPool) error {
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return errors.New("pkcs7: No certificate for signer")
	}
	signedData, signingTime, err := verifySignedAttributes(p7, signer, ee)
	if err != nil {
		return err
	}
	if truststore != nil {
		if _, err := verifyCertChain(ee, p7.Certificates, truststore, signingTime); err != nil {
			return err
		}
	}
	sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
}

// verifySignedAttributes validates the authenticated (signed) attributes of a
// SignerInfo and returns the bytes covered by the EncryptedDigest, together
// with the signing time carried by the signing time attribute (the current
// UTC time when the attribute is absent).
//
// It enforces, per RFC 5652 section 11.1:
//
//   - When authenticated attributes are present, the content type attribute
//     MUST be present exactly once, hold exactly one value, and that value
//     MUST equal the content type of the encapsulated content. Duplicate
//     attributes and multi-valued attributes are rejected instead of having
//     one of their values picked silently.
//   - The message digest and signing time attributes, when present, are
//     singleton, single-valued attributes as well.
//   - The digest algorithm and the digest encryption algorithm must resolve
//     to the same hash, so the algorithms cannot be made to disagree and
//     silently downgrade the hash used for verification.
func verifySignedAttributes(p7 *PKCS7, signer signerInfo, ee *x509.Certificate) (signedData []byte, signingTime time.Time, err error) {
	// The two algorithm identifiers must agree on the hash they use. This is
	// checked up front, before any hash is computed, so that a mismatched
	// pair can never be downgraded to a weaker hash silently.
	if err := verifyAlgorithmCombination(signer.DigestAlgorithm, signer.DigestEncryptionAlgorithm); err != nil {
		return nil, time.Time{}, err
	}

	signedData = p7.Content
	signingTime = time.Now().UTC()
	if len(signer.AuthenticatedAttributes) == 0 {
		return signedData, signingTime, nil
	}

	// The content type attribute binds the authenticated attributes to the
	// encapsulated content. It must be present exactly once and carry a
	// single value equal to the SignedData content type.
	var contentType asn1.ObjectIdentifier
	if err := unmarshalSingletonAttribute(signer.AuthenticatedAttributes, OIDAttributeContentType, &contentType); err != nil {
		return nil, time.Time{}, err
	}
	encapsulatedContentType, err := getEncapsulatedContentType(p7)
	if err != nil {
		return nil, time.Time{}, err
	}
	if !contentType.Equal(encapsulatedContentType) {
		return nil, time.Time{}, &ContentTypeMismatchError{
			Expected: encapsulatedContentType,
			Actual:   contentType,
		}
	}

	var digest []byte
	if err := unmarshalSingletonAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
		return nil, time.Time{}, err
	}
	hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, time.Time{}, err
	}
	computed, err := calculateHash(p7.Hasher, hash, p7.Content)
	if err != nil {
		return nil, time.Time{}, err
	}
	if subtle.ConstantTimeCompare(digest, computed) != 1 {
		return nil, time.Time{}, &MessageDigestMismatchError{
			ExpectedDigest: digest,
			ActualDigest:   computed,
		}
	}

	signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
	if err != nil {
		return nil, time.Time{}, err
	}

	// The signing time attribute is optional, but if present it must be a
	// singleton, single-valued attribute.
	var attrSigningTime time.Time
	if err := unmarshalSingletonAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &attrSigningTime); err != nil {
		var invalid *InvalidAttributeError
		if !errors.As(err, &invalid) || invalid.Reason != invalidAttributeReasonMissing {
			return nil, time.Time{}, err
		}
	} else {
		signingTime = attrSigningTime
		// signing time found, performing validity check
		if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
			return nil, time.Time{}, &SigningTimeNotValidError{
				SigningTime: signingTime,
				NotBefore:   ee.NotBefore,
				NotAfter:    ee.NotAfter,
			}
		}
	}

	return signedData, signingTime, nil
}

const (
	invalidAttributeReasonMissing    = "attribute not in attributes"
	invalidAttributeReasonDuplicate  = "attribute type occurs more than once"
	invalidAttributeReasonMultiValue = "attribute value set must contain exactly one value"
)

// unmarshalSingletonAttribute decodes the single value of an authenticated
// attribute. It rejects SignerInfos where the attribute type occurs more
// than once, or where its SET OF value contains anything other than exactly
// one value, instead of silently using the first occurrence.
func unmarshalSingletonAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	var matched *attribute
	for i := range attrs {
		if !attrs[i].Type.Equal(attributeType) {
			continue
		}
		if matched != nil {
			return &InvalidAttributeError{
				Type:   attributeType,
				Reason: invalidAttributeReasonDuplicate,
			}
		}
		matched = &attrs[i]
	}
	if matched == nil {
		return &InvalidAttributeError{
			Type:   attributeType,
			Reason: invalidAttributeReasonMissing,
		}
	}

	// The attribute value is encoded as a SET OF. RFC 5652 requires the
	// content type, message digest and signing time attributes to carry a
	// single value; any extra value would be ignored by a lenient parser and
	// can therefore be used to smuggle a conflicting value past verification.
	rest := matched.Value.Bytes
	count := 0
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &rv); err != nil {
			return &InvalidAttributeError{
				Type:   attributeType,
				Reason: "attribute value set is malformed: " + err.Error(),
			}
		}
		count++
	}
	if count != 1 {
		return &InvalidAttributeError{
			Type:   attributeType,
			Reason: invalidAttributeReasonMultiValue,
		}
	}

	if _, err := asn1.Unmarshal(matched.Value.Bytes, out); err != nil {
		return &InvalidAttributeError{
			Type:   attributeType,
			Reason: "attribute value cannot be decoded: " + err.Error(),
		}
	}
	return nil
}

// getEncapsulatedContentType returns the content type of the content
// encapsulated in the SignedData structure.
func getEncapsulatedContentType(p7 *PKCS7) (asn1.ObjectIdentifier, error) {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return nil, errors.New("pkcs7: payload is not signedData content")
	}
	return sd.ContentInfo.ContentType, nil
}

// verifyAlgorithmCombination ensures that the digest algorithm identifier and
// the digest encryption algorithm identifier of a SignerInfo resolve to the
// same hash. A message whose identifiers disagree would otherwise be accepted
// while the signature is checked with a hash chosen solely from the
// encryption identifier, i.e. silently downgraded relative to the advertised
// digest algorithm.
func verifyAlgorithmCombination(digest, digestEncryption pkix.AlgorithmIdentifier) error {
	digestHash, err := getHashForOID(digest.Algorithm)
	if err != nil {
		return err
	}
	// The generic rsaEncryption identifier (1.2.840.113549.1.1.1) names no
	// hash of its own: the hash is taken from the digest algorithm. This
	// encoding is produced by common tooling (including OpenSSL) and must
	// continue to be accepted; there is no second hash that could disagree.
	if digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSA) {
		return nil
	}
	// The named EC public key identifiers (1.2.840.10045.3.1.7 and friends)
	// only describe the curve, not a hash: again, the digest algorithm is
	// the sole source of the hash.
	if isECPublicKeyOID(digestEncryption.Algorithm) {
		return nil
	}
	encryptionHash, err := getHashForOID(digestEncryption.Algorithm)
	if err != nil {
		return err
	}
	if digestHash != encryptionHash {
		return &AlgorithmCombinationError{
			DigestAlgorithm:           digest.Algorithm,
			DigestEncryptionAlgorithm: digestEncryption.Algorithm,
		}
	}
	return nil
}

// isECPublicKeyOID reports whether the OID identifies an EC public key type
// without embedding a hash, as used in the DigestEncryptionAlgorithm field of
// some SignerInfo structures.
func isECPublicKeyOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDEncryptionAlgorithmECDSAP256) ||
		oid.Equal(OIDEncryptionAlgorithmECDSAP384) ||
		oid.Equal(OIDEncryptionAlgorithmECDSAP521)
}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (p7 *PKCS7) GetOnlySigner() *x509.Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

// UnmarshalSignedAttribute decodes a single attribute from the signer info
func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

func parseSignedData(data []byte) (*PKCS7, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}
	// fmt.Printf("--> Signed Data Version %d\n", sd.Version)

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	// Compound octet string
	if compound.IsCompound {
		if compound.Tag == 4 {
			for len(compound.Bytes) > 0 {
				var cdata asn1.RawValue
				if _, err = asn1.Unmarshal(compound.Bytes, &cdata); err != nil {
					return nil, err
				}
				content = append(content, cdata.Bytes...)
				compound.Bytes = compound.Bytes[len(cdata.FullBytes):]
			}
		} else {
			content = compound.Bytes
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

// verifyCertChain takes an end-entity certs, a list of potential intermediates and a
// truststore, and built all potential chains between the EE and a trusted root.
//
// When verifying chains that may have expired, currentTime can be set to a past date
// to allow the verification to pass. If unset, currentTime is set to the current UTC time.
func verifyCertChain(ee *x509.Certificate, certs []*x509.Certificate, truststore *x509.CertPool, currentTime time.Time) (chains [][]*x509.Certificate, err error) {
	intermediates := x509.NewCertPool()
	for _, intermediate := range certs {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   currentTime,
	}
	chains, err = ee.Verify(verifyOptions)
	if err != nil {
		return chains, fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
	}
	return
}

// MessageDigestMismatchError is returned when the signer data digest does not
// match the computed digest for the contained content
type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

func getSignatureAlgorithm(digestEncryption, digest pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA1):
		return x509.ECDSAWithSHA1, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA256):
		return x509.ECDSAWithSHA256, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA384):
		return x509.ECDSAWithSHA384, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA512):
		return x509.ECDSAWithSHA512, nil
	case digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSA),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA1),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA256),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA384),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA512):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1), digest.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA1):
			return x509.SHA1WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256), digest.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA256):
			return x509.SHA256WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA384), digest.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA384):
			return x509.SHA384WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA512), digest.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA512):
			return x509.SHA512WithRSA, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmDSA),
		digestEncryption.Algorithm.Equal(OIDDigestAlgorithmDSASHA1):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1):
			return x509.DSAWithSHA1, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return x509.DSAWithSHA256, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP256),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP384),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP521):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1):
			return x509.ECDSAWithSHA1, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return x509.ECDSAWithSHA256, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA384):
			return x509.ECDSAWithSHA384, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA512):
			return x509.ECDSAWithSHA512, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	default:
		return -1, fmt.Errorf("pkcs7: unsupported algorithm %q",
			digestEncryption.Algorithm.String())
	}
}

func getCertFromCertsByIssuerAndSerial(certs []*x509.Certificate, ias issuerAndSerial) *x509.Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return errors.New("pkcs7: attribute type not in attributes")
}

func calculateHash(hasher Hasher, hashFunc crypto.Hash, content []byte) (computed []byte, err error) {
	if hasher != nil {
		computed, err = hasher.Hash(hashFunc, bytes.NewReader(content))
	} else {
		if !hashFunc.Available() {
			return nil, fmt.Errorf("hash function %v not available", hashFunc)
		}

		h := hashFunc.New()
		_, _ = h.Write(content)
		computed = h.Sum(nil)
	}

	return
}
