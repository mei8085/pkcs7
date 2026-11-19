package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ErrInvalidOAEPParameters is returned when the RSAES-OAEP parameters of a
// key encryption algorithm identifier are missing, malformed, conflicting or
// otherwise unsupported. It is returned before any RSA operation is performed
// on the encrypted key, so a caller can report the problem without having
// attempted (and possibly leaked information about) a decryption.
var ErrInvalidOAEPParameters = errors.New("pkcs7: invalid RSA OAEP parameters")

// rsaOAEPAlgorithmParameters is the ASN.1 shape of RSAES-OAEP-params
// (RFC 4055, section 4.1; RFC 8017, appendix A.2.1):
//
//	RSAES-OAEP-params ::= SEQUENCE {
//	    hashAlgorithm    [0] HashAlgorithm    DEFAULT sha1,
//	    maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
//	    pSourceAlgorithm [2] PSourceAlgorithm DEFAULT pSpecifiedEmpty
//	}
//
// The encoding/asn1 package only understands integer DEFAULT values, so the
// DEFAULT tags are not expressed here. Parameters that should use their
// default value are left zero, which marshals to an omitted (and therefore
// defaulted) field. Parsing is done separately and strictly by
// parseRSAOAEPParameters, which also enforces the DEFAULT values and rejects
// fields this struct could silently ignore.
type rsaOAEPAlgorithmParameters struct {
	HashFunc    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenFunc pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	PSourceFunc pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
}

// rsaOAEPParameters is the fully resolved RSAES-OAEP parameter contract. The
// same values are used both to declare the parameters in an envelope and to
// perform the RSA operation, which keeps the declaration and the computation
// in sync:
//
//   - Hash is the digest algorithm used for OAEP and for the label hash.
//   - MGFHash is the digest algorithm used by the MGF1 mask generation
//     function. It is never left zero: when the maskGenAlgorithm field is
//     absent the RFC 4055 default (SHA-1) applies, even if Hash is not SHA-1.
//   - Label is the OAEP label ("encoding parameters"). The default is empty.
type rsaOAEPParameters struct {
	Hash    crypto.Hash
	MGFHash crypto.Hash
	Label   []byte
}

// defaultRSAOAEPParameters returns the parameters implied by an empty
// RSAES-OAEP-params SEQUENCE: SHA-1 with MGF1-SHA-1 and an empty label.
func defaultRSAOAEPParameters() rsaOAEPParameters {
	return rsaOAEPParameters{
		Hash:    crypto.SHA1,
		MGFHash: crypto.SHA1,
	}
}

// hashFromOID maps a digest algorithm OID to a crypto.Hash, rejecting
// algorithms that cannot be used with OAEP here.
func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	var hash crypto.Hash
	switch {
	case oid.Equal(OIDDigestAlgorithmSHA1):
		hash = crypto.SHA1
	case oid.Equal(OIDDigestAlgorithmSHA224):
		hash = crypto.SHA224
	case oid.Equal(OIDDigestAlgorithmSHA256):
		hash = crypto.SHA256
	case oid.Equal(OIDDigestAlgorithmSHA384):
		hash = crypto.SHA384
	case oid.Equal(OIDDigestAlgorithmSHA512):
		hash = crypto.SHA512
	default:
		return crypto.Hash(0), fmt.Errorf("%w: unsupported digest algorithm %v", ErrInvalidOAEPParameters, oid)
	}
	if !hash.Available() {
		return crypto.Hash(0), fmt.Errorf("%w: digest algorithm %v is not available", ErrInvalidOAEPParameters, oid)
	}
	return hash, nil
}

// oidForHash maps a crypto.Hash to the digest algorithm OID used in RSAES-OAEP
// parameters.
func oidForHash(hash crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch hash {
	case crypto.SHA1:
		return OIDDigestAlgorithmSHA1, nil
	case crypto.SHA224:
		return OIDDigestAlgorithmSHA224, nil
	case crypto.SHA256:
		return OIDDigestAlgorithmSHA256, nil
	case crypto.SHA384:
		return OIDDigestAlgorithmSHA384, nil
	case crypto.SHA512:
		return OIDDigestAlgorithmSHA512, nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedKeyEncryptionHash, hash)
	}
}

// digestAlgorithmIdentifier builds the AlgorithmIdentifier for a digest
// algorithm, with the conventional NULL parameters.
func digestAlgorithmIdentifier(hash crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	oid, err := oidForHash(hash)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	return pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: asn1.NullBytes},
	}, nil
}

// checkDigestAlgorithmParameters accepts the two encodings used for digest
// algorithm parameters: absent, or NULL. Anything else is not a digest
// algorithm identifier we understand and is rejected instead of being
// ignored.
func checkDigestAlgorithmParameters(params asn1.RawValue) error {
	if len(params.FullBytes) == 0 || bytes.Equal(params.FullBytes, asn1.NullBytes) {
		return nil
	}
	return fmt.Errorf("%w: digest algorithm parameters must be absent or NULL", ErrInvalidOAEPParameters)
}

// parseDigestAlgorithm parses an AlgorithmIdentifier carrying a digest
// algorithm and returns the corresponding crypto.Hash.
func parseDigestAlgorithm(content []byte, what string) (crypto.Hash, error) {
	var ai pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(content, &ai)
	if err != nil {
		return crypto.Hash(0), fmt.Errorf("%w: cannot parse %s algorithm identifier: %v", ErrInvalidOAEPParameters, what, err)
	}
	if len(rest) != 0 {
		return crypto.Hash(0), fmt.Errorf("%w: trailing data after %s algorithm identifier", ErrInvalidOAEPParameters, what)
	}
	hash, err := hashFromOID(ai.Algorithm)
	if err != nil {
		return crypto.Hash(0), err
	}
	if err := checkDigestAlgorithmParameters(ai.Parameters); err != nil {
		return crypto.Hash(0), err
	}
	return hash, nil
}

// parseRSAOAEPParameters strictly decodes and validates RSAES-OAEP-params.
//
// An absent parameters field is rejected: without it the key encryption
// algorithm does not state which OAEP variant it uses, and silently assuming
// defaults would let a declaration mismatch go unnoticed. An empty SEQUENCE,
// on the other hand, is the canonical DER encoding of the all-default
// parameters and is accepted.
func parseRSAOAEPParameters(parameters asn1.RawValue) (rsaOAEPParameters, error) {
	params := defaultRSAOAEPParameters()

	if len(parameters.FullBytes) == 0 {
		return params, fmt.Errorf("%w: RSAES-OAEP parameters are missing", ErrInvalidOAEPParameters)
	}

	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(parameters.FullBytes, &seq)
	if err != nil {
		return params, fmt.Errorf("%w: %v", ErrInvalidOAEPParameters, err)
	}
	if len(rest) != 0 {
		return params, fmt.Errorf("%w: trailing data after RSAES-OAEP parameters", ErrInvalidOAEPParameters)
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return params, fmt.Errorf("%w: RSAES-OAEP parameters are not a SEQUENCE", ErrInvalidOAEPParameters)
	}

	// Walk the fields by hand instead of unmarshaling into the struct: the
	// encoding/asn1 package ignores unknown trailing elements and would
	// therefore accept duplicated or unrecognized parameters silently.
	fields := seq.Bytes
	lastTag := -1
	for len(fields) > 0 {
		var field asn1.RawValue
		rest, err := asn1.Unmarshal(fields, &field)
		if err != nil {
			return params, fmt.Errorf("%w: malformed parameter field: %v", ErrInvalidOAEPParameters, err)
		}
		fields = rest

		if field.Class != asn1.ClassContextSpecific || !field.IsCompound || field.Tag < 0 || field.Tag > 2 {
			return params, fmt.Errorf("%w: unrecognized parameter field (class %d, tag %d)",
				ErrInvalidOAEPParameters, field.Class, field.Tag)
		}
		if field.Tag <= lastTag {
			return params, fmt.Errorf("%w: duplicate or out-of-order parameter field [%d]",
				ErrInvalidOAEPParameters, field.Tag)
		}
		lastTag = field.Tag

		switch field.Tag {
		case 0:
			hash, err := parseDigestAlgorithm(field.Bytes, "hash")
			if err != nil {
				return params, err
			}
			params.Hash = hash
		case 1:
			mgfHash, err := parseOAEPMaskGenAlgorithm(field.Bytes)
			if err != nil {
				return params, err
			}
			params.MGFHash = mgfHash
		case 2:
			label, err := parseOAEPPSourceAlgorithm(field.Bytes)
			if err != nil {
				return params, err
			}
			params.Label = label
		}
	}

	return params, nil
}

// parseOAEPMaskGenAlgorithm parses the maskGenAlgorithm field. Only MGF1 is
// defined for RSAES-OAEP, and its parameters must identify the digest used by
// MGF1; a missing digest is an error rather than an implicit default because
// the whole field being absent is what selects the default MGF1-SHA-1.
func parseOAEPMaskGenAlgorithm(content []byte) (crypto.Hash, error) {
	var ai pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(content, &ai)
	if err != nil {
		return crypto.Hash(0), fmt.Errorf("%w: cannot parse mask generation algorithm identifier: %v", ErrInvalidOAEPParameters, err)
	}
	if len(rest) != 0 {
		return crypto.Hash(0), fmt.Errorf("%w: trailing data after mask generation algorithm identifier", ErrInvalidOAEPParameters)
	}
	if !ai.Algorithm.Equal(OIDMaskGenAlgorithmMGF1) {
		return crypto.Hash(0), fmt.Errorf("%w: unsupported mask generation function %v", ErrInvalidOAEPParameters, ai.Algorithm)
	}
	if len(ai.Parameters.FullBytes) == 0 {
		return crypto.Hash(0), fmt.Errorf("%w: MGF1 parameters are missing the digest algorithm", ErrInvalidOAEPParameters)
	}
	return parseDigestAlgorithm(ai.Parameters.FullBytes, "MGF1 digest")
}

// parseOAEPPSourceAlgorithm parses the pSourceAlgorithm field. Only
// id-pSpecified is defined, and its parameter is the label as an OCTET
// STRING. A missing parameter is an error, since the field's absence is what
// selects the default empty label.
func parseOAEPPSourceAlgorithm(content []byte) ([]byte, error) {
	var ai pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(content, &ai)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot parse pSource algorithm identifier: %v", ErrInvalidOAEPParameters, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing data after pSource algorithm identifier", ErrInvalidOAEPParameters)
	}
	if !ai.Algorithm.Equal(OIDPSourceAlgorithmP) {
		return nil, fmt.Errorf("%w: unsupported pSource algorithm %v", ErrInvalidOAEPParameters, ai.Algorithm)
	}
	if len(ai.Parameters.FullBytes) == 0 {
		return nil, fmt.Errorf("%w: pSpecified parameters are missing the label", ErrInvalidOAEPParameters)
	}
	var label []byte
	rest, err = asn1.Unmarshal(ai.Parameters.FullBytes, &label)
	if err != nil {
		return nil, fmt.Errorf("%w: pSpecified label is not an OCTET STRING: %v", ErrInvalidOAEPParameters, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing data after pSpecified label", ErrInvalidOAEPParameters)
	}
	return label, nil
}

// getParametersForKeyEncryptionAlgorithm returns the parameters that Encrypt
// writes for a key encryption algorithm and digest.
//
// For RSAES-OAEP this is exactly the contract encryptKey performs, so the
// digest, MGF1 digest and label in the envelope match the operation. For any
// other algorithm no parameters are used.
func getParametersForKeyEncryptionAlgorithm(algorithm asn1.ObjectIdentifier, hash crypto.Hash) (asn1.RawValue, error) {
	if !algorithm.Equal(OIDEncryptionAlgorithmRSAESOAEP) {
		return asn1.RawValue{}, nil // return empty; not used
	}
	return marshalRSAOAEPParameters(rsaOAEPParametersForEncryption(hash))
}

// rsaOAEPParametersForEncryption returns the RSAES-OAEP parameters that
// rsa.EncryptOAEP can actually perform: the same digest for the OAEP hash and
// for MGF1, and an empty label.
//
// This value is the single source of truth for the symmetric part of the
// envelope: it is both encoded into the recipient's keyEncryptionAlgorithm
// and used to drive the RSA operation, so the declaration and the computation
// cannot drift apart.
func rsaOAEPParametersForEncryption(hash crypto.Hash) rsaOAEPParameters {
	return rsaOAEPParameters{
		Hash:    hash,
		MGFHash: hash,
	}
}

// marshalRSAOAEPParameters encodes RSAES-OAEP-params exactly as the given
// contract describes them, omitting fields that are equal to their DEFAULT
// value (canonical DER).
//
// For the parameters produced by rsaOAEPParametersForEncryption this means:
// SHA-1 yields the empty SEQUENCE (all defaults), and any other digest yields
// an explicit hashAlgorithm plus an explicit MGF1 maskGenAlgorithm carrying
// the same digest. That is what makes the resulting envelope interoperable
// with implementations that apply the RFC 4055 defaults strictly.
func marshalRSAOAEPParameters(params rsaOAEPParameters) (asn1.RawValue, error) {
	hashID, err := digestAlgorithmIdentifier(params.Hash)
	if err != nil {
		return asn1.RawValue{}, err
	}
	mgfHashID, err := digestAlgorithmIdentifier(params.MGFHash)
	if err != nil {
		return asn1.RawValue{}, err
	}

	var encoded rsaOAEPAlgorithmParameters
	if params.Hash != crypto.SHA1 {
		// hashAlgorithm is no longer the default and must be written out.
		encoded.HashFunc = hashID
	}
	if params.MGFHash != crypto.SHA1 {
		// maskGenAlgorithm is no longer the default MGF1-SHA-1 and must be
		// written out, including the digest MGF1 uses.
		mgfParams, err := asn1.Marshal(mgfHashID)
		if err != nil {
			return asn1.RawValue{}, fmt.Errorf("pkcs7: failed marshaling MGF1 parameters: %v", err)
		}
		encoded.MaskGenFunc = pkix.AlgorithmIdentifier{
			Algorithm:  OIDMaskGenAlgorithmMGF1,
			Parameters: asn1.RawValue{FullBytes: mgfParams},
		}
	}
	if len(params.Label) != 0 {
		// pSourceAlgorithm is no longer the default pSpecifiedEmpty.
		label, err := asn1.Marshal(params.Label)
		if err != nil {
			return asn1.RawValue{}, fmt.Errorf("pkcs7: failed marshaling OAEP label: %v", err)
		}
		encoded.PSourceFunc = pkix.AlgorithmIdentifier{
			Algorithm:  OIDPSourceAlgorithmP,
			Parameters: asn1.RawValue{FullBytes: label},
		}
	}

	b, err := asn1.Marshal(encoded)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("pkcs7: failed marshaling RSAES-OAEP parameters: %v", err)
	}
	return asn1.RawValue{FullBytes: b}, nil
}
