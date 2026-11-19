package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"testing"
)

// oaepSequence builds the DER encoding of an RSAES-OAEP-params SEQUENCE from
// raw field encodings, in the order given. Each field must already be a
// complete, explicitly tagged element.
func oaepSequence(fields ...asn1.RawValue) asn1.RawValue {
	var body []byte
	for _, f := range fields {
		body = append(body, f.FullBytes...)
	}
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		panic(err)
	}
	return asn1.RawValue{FullBytes: seq}
}

// contextField encodes value with an explicit context-specific tag, as used
// for the [0], [1] and [2] fields of RSAES-OAEP-params.
func contextField(tag int, inner []byte) asn1.RawValue {
	b, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner,
	})
	if err != nil {
		panic(err)
	}
	return asn1.RawValue{FullBytes: b}
}

// digestIdentifier encodes a digest AlgorithmIdentifier with NULL parameters,
// the encoding used inside RSAES-OAEP-params.
func digestIdentifier(hash crypto.Hash) []byte {
	ai, err := digestAlgorithmIdentifier(hash)
	if err != nil {
		panic(err)
	}
	b, err := asn1.Marshal(ai)
	if err != nil {
		panic(err)
	}
	return b
}

// mgf1Identifier encodes maskGenAlgorithm = mgf1 with the given digest.
func mgf1Identifier(hash crypto.Hash) []byte {
	inner, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  OIDMaskGenAlgorithmMGF1,
		Parameters: asn1.RawValue{FullBytes: digestIdentifier(hash)},
	})
	if err != nil {
		panic(err)
	}
	return inner
}

// pSpecifiedIdentifier encodes pSourceAlgorithm = pSpecified with a label.
func pSpecifiedIdentifier(label []byte) []byte {
	inner, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  OIDPSourceAlgorithmP,
		Parameters: asn1.RawValue{FullBytes: mustMarshal(label)},
	})
	if err != nil {
		panic(err)
	}
	return inner
}

func mustMarshal(v interface{}) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// TestParseRSAOAEPParametersRejects covers parameter sets that must be
// rejected before any RSA operation: missing parameters, fields the parser
// does not understand, fields that cannot be combined, and duplicated or
// out-of-order fields.
func TestParseRSAOAEPParametersRejects(t *testing.T) {
	sha1Field := contextField(0, digestIdentifier(crypto.SHA1))
	sha256Field := contextField(0, digestIdentifier(crypto.SHA256))

	tests := []struct {
		name   string
		params asn1.RawValue
	}{
		{
			name:   "absent parameters",
			params: asn1.RawValue{},
		},
		{
			name:   "parameters are not a sequence",
			params: asn1.RawValue{FullBytes: mustMarshal(42)},
		},
		{
			name:   "trailing data after sequence",
			params: asn1.RawValue{FullBytes: append(mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true}), 0x05, 0x00)},
		},
		{
			name:   "unknown context field",
			params: oaepSequence(contextField(3, mustMarshal(1))),
		},
		{
			name:   "unknown digest algorithm",
			params: oaepSequence(contextField(0, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}))),
		},
		{
			name:   "digest parameters that are neither absent nor NULL",
			params: oaepSequence(contextField(0, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: OIDDigestAlgorithmSHA256, Parameters: asn1.RawValue{FullBytes: mustMarshal("bogus")}}))),
		},
		{
			name:   "unsupported mask generation function",
			params: oaepSequence(sha256Field, contextField(1, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 5}}))),
		},
		{
			name:   "MGF1 without a digest",
			params: oaepSequence(sha256Field, contextField(1, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: OIDMaskGenAlgorithmMGF1}))),
		},
		{
			name:   "MGF1 with an unknown digest",
			params: oaepSequence(sha256Field, contextField(1, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: OIDMaskGenAlgorithmMGF1, Parameters: asn1.RawValue{FullBytes: mustMarshal(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 6}})}}))),
		},
		{
			name:   "unsupported pSource algorithm",
			params: oaepSequence(sha256Field, contextField(2, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 7}}))),
		},
		{
			name:   "pSpecified without a label",
			params: oaepSequence(sha256Field, contextField(2, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: OIDPSourceAlgorithmP}))),
		},
		{
			name:   "pSpecified label is not an OCTET STRING",
			params: oaepSequence(sha256Field, contextField(2, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: OIDPSourceAlgorithmP, Parameters: asn1.RawValue{FullBytes: mustMarshal(1)}}))),
		},
		{
			name:   "duplicate hashAlgorithm",
			params: oaepSequence(sha1Field, sha256Field),
		},
		{
			name:   "fields out of order",
			params: oaepSequence(contextField(1, mgf1Identifier(crypto.SHA256)), sha256Field),
		},
		{
			name:   "non-context field inside parameters",
			params: oaepSequence(asn1.RawValue{FullBytes: mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true})}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRSAOAEPParameters(tt.params)
			if err == nil {
				t.Fatalf("parseRSAOAEPParameters() accepted malformed parameters")
			}
			if !errors.Is(err, ErrInvalidOAEPParameters) {
				t.Errorf("parseRSAOAEPParameters() error = %v, want ErrInvalidOAEPParameters", err)
			}
		})
	}
}

// TestParseRSAOAEPParametersAccepts covers the legal encodings, including the
// all-default empty SEQUENCE and explicitly written fields that are equal to
// their defaults.
func TestParseRSAOAEPParametersAccepts(t *testing.T) {
	tests := []struct {
		name    string
		params  asn1.RawValue
		hash    crypto.Hash
		mgfHash crypto.Hash
		label   []byte
	}{
		{
			name:    "all defaults",
			params:  oaepSequence(),
			hash:    crypto.SHA1,
			mgfHash: crypto.SHA1,
		},
		{
			name:    "explicit default digest",
			params:  oaepSequence(contextField(0, digestIdentifier(crypto.SHA1))),
			hash:    crypto.SHA1,
			mgfHash: crypto.SHA1,
		},
		{
			name:    "explicit digest and MGF1",
			params:  oaepSequence(contextField(0, digestIdentifier(crypto.SHA256)), contextField(1, mgf1Identifier(crypto.SHA256))),
			hash:    crypto.SHA256,
			mgfHash: crypto.SHA256,
		},
		{
			name:    "explicit MGF1-SHA1 with SHA-256 digest",
			params:  oaepSequence(contextField(0, digestIdentifier(crypto.SHA256)), contextField(1, mgf1Identifier(crypto.SHA1))),
			hash:    crypto.SHA256,
			mgfHash: crypto.SHA1,
		},
		{
			name:    "explicit empty pSpecified",
			params:  oaepSequence(contextField(0, digestIdentifier(crypto.SHA256)), contextField(1, mgf1Identifier(crypto.SHA256)), contextField(2, pSpecifiedIdentifier(nil))),
			hash:    crypto.SHA256,
			mgfHash: crypto.SHA256,
			label:   []byte{},
		},
		{
			name:    "explicit label",
			params:  oaepSequence(contextField(2, pSpecifiedIdentifier([]byte("label")))),
			hash:    crypto.SHA1,
			mgfHash: crypto.SHA1,
			label:   []byte("label"),
		},
		{
			name:    "digest parameters absent instead of NULL",
			params:  oaepSequence(contextField(0, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: OIDDigestAlgorithmSHA384}))),
			hash:    crypto.SHA384,
			mgfHash: crypto.SHA1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := parseRSAOAEPParameters(tt.params)
			if err != nil {
				t.Fatalf("parseRSAOAEPParameters() error = %v", err)
			}
			if params.Hash != tt.hash {
				t.Errorf("Hash = %v, want %v", params.Hash, tt.hash)
			}
			if params.MGFHash != tt.mgfHash {
				t.Errorf("MGFHash = %v, want %v", params.MGFHash, tt.mgfHash)
			}
			if !bytes.Equal(params.Label, tt.label) {
				t.Errorf("Label = %x, want %x", params.Label, tt.label)
			}
		})
	}
}

// buildEnvelopeForParameters creates an enveloped-data structure whose single
// recipient declares the given key encryption algorithm identifier. The
// encrypted key is produced with the given parameters, so a successful round
// trip is only possible if decryption honours the declaration that is also
// written into the algorithm identifier.
func buildEnvelopeForParameters(t *testing.T, fixture TestFixture, algorithm pkix.AlgorithmIdentifier, params rsaOAEPParameters, contentKey []byte) *PKCS7 {
	t.Helper()
	_, eci := mustEncryptAESCBC(t, []byte("the plaintext"), contentKey)
	// Only contracts that rsa.EncryptOAEP can produce are supported here:
	// the same digest for OAEP and MGF1, which is what the declared
	// parameters must match for a round trip to be meaningful.
	if params.MGFHash != params.Hash {
		t.Fatalf("buildEnvelopeForParameters: unsupported MGF1 digest %v for OAEP digest %v", params.MGFHash, params.Hash)
	}
	encryptedKey, err := rsa.EncryptOAEP(params.Hash.New(), rand.Reader, &fixture.PrivateKey.PublicKey, contentKey, params.Label)
	if err != nil {
		t.Fatal(err)
	}
	ias, err := cert2issuerAndSerial(fixture.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	ed := envelopedData{
		Version: 0,
		RecipientInfos: []recipientInfo{{
			Version:                0,
			IssuerAndSerialNumber:  ias,
			KeyEncryptionAlgorithm: algorithm,
			EncryptedKey:           encryptedKey,
		}},
		EncryptedContentInfo: *eci,
	}
	return &PKCS7{raw: ed}
}

// mustEncryptAESCBC encrypts content with a caller-provided AES-256-CBC key.
func mustEncryptAESCBC(t *testing.T, content, key []byte) ([]byte, *encryptedContentInfo) {
	t.Helper()
	old := ContentEncryptionAlgorithm
	ContentEncryptionAlgorithm = EncryptionAlgorithmAES256CBC
	defer func() { ContentEncryptionAlgorithm = old }()
	_, eci, err := encryptAESCBC(content, key)
	if err != nil {
		t.Fatal(err)
	}
	return content, eci
}

// TestDecryptRejectsBadOAEPParametersEndToEnd checks that a malformed or
// conflicting keyEncryptionAlgorithm makes Decrypt fail before any RSA
// operation, that no plaintext is returned, and that the same PKCS7 object
// can still decrypt a well-formed envelope afterwards ("the caller can carry
// on with the next envelope").
func TestDecryptRejectsBadOAEPParametersEndToEnd(t *testing.T) {
	fixture := UnmarshalTestFixture(RSAOAEPSHA256EncryptedTestFixture)
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}

	goodParams := rsaOAEPParametersForEncryption(crypto.SHA256)
	goodAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm:  OIDEncryptionAlgorithmRSAESOAEP,
		Parameters: mustMarshalRaw(t, goodParams),
	}
	good := buildEnvelopeForParameters(t, fixture, goodAlgorithm, goodParams, contentKey)
	if out, err := good.Decrypt(fixture.Certificate, fixture.PrivateKey); err != nil || !bytes.Equal(out, []byte("the plaintext")) {
		t.Fatalf("baseline envelope did not decrypt: out=%q err=%v", out, err)
	}

	badAlgorithms := []struct {
		name      string
		algorithm pkix.AlgorithmIdentifier
	}{
		{
			name: "missing parameters",
			algorithm: pkix.AlgorithmIdentifier{
				Algorithm: OIDEncryptionAlgorithmRSAESOAEP,
			},
		},
		{
			name: "unknown digest",
			algorithm: pkix.AlgorithmIdentifier{
				Algorithm:  OIDEncryptionAlgorithmRSAESOAEP,
				Parameters: oaepSequence(contextField(0, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}))),
			},
		},
		{
			name: "duplicate digest field",
			algorithm: pkix.AlgorithmIdentifier{
				Algorithm: OIDEncryptionAlgorithmRSAESOAEP,
				Parameters: oaepSequence(
					contextField(0, digestIdentifier(crypto.SHA256)),
					contextField(0, digestIdentifier(crypto.SHA384)),
				),
			},
		},
		{
			name: "unsupported mask generation function",
			algorithm: pkix.AlgorithmIdentifier{
				Algorithm: OIDEncryptionAlgorithmRSAESOAEP,
				Parameters: oaepSequence(
					contextField(0, digestIdentifier(crypto.SHA256)),
					contextField(1, mustMarshal(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 5}})),
				),
			},
		},
	}

	for _, tt := range badAlgorithms {
		t.Run(tt.name, func(t *testing.T) {
			// The encrypted key is valid for goodParams, so a decryption
			// that ignored the malformed declaration would succeed; the only
			// acceptable outcome is the parameter error.
			envelope := buildEnvelopeForParameters(t, fixture, tt.algorithm, goodParams, contentKey)

			out, err := envelope.Decrypt(fixture.Certificate, fixture.PrivateKey)
			if err == nil {
				t.Fatalf("Decrypt() accepted invalid OAEP parameters, returned %q", out)
			}
			if out != nil {
				t.Errorf("Decrypt() returned %q together with an error", out)
			}
			if !errors.Is(err, ErrInvalidOAEPParameters) {
				t.Errorf("Decrypt() error = %v, want ErrInvalidOAEPParameters", err)
			}

			// The same object must remain usable for a well-formed envelope.
			if out, err := good.Decrypt(fixture.Certificate, fixture.PrivateKey); err != nil || !bytes.Equal(out, []byte("the plaintext")) {
				t.Errorf("subsequent valid decryption failed: out=%q err=%v", out, err)
			}
		})
	}
}

// TestDecryptRejectsDeclaredMGFMismatchEndToEnd builds the exact defect this
// change fixes: parameters that declare SHA-256 for the OAEP digest with the
// default MGF1-SHA-1, while the key was encrypted with MGF1-SHA-256. Such an
// input must not decrypt silently.
func TestDecryptRejectsDeclaredMGFMismatchEndToEnd(t *testing.T) {
	fixture := UnmarshalTestFixture(RSAOAEPSHA256EncryptedTestFixture)
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}

	// What the fixed encoder writes: explicit hashAlgorithm and explicit
	// MGF1-SHA-256.
	actual := rsaOAEPParametersForEncryption(crypto.SHA256)
	// What the envelope declares: SHA-256 digest, MGF1-SHA-1 default.
	declared := oaepSequence(contextField(0, digestIdentifier(crypto.SHA256)))
	algorithm := pkix.AlgorithmIdentifier{
		Algorithm:  OIDEncryptionAlgorithmRSAESOAEP,
		Parameters: declared,
	}

	envelope := buildEnvelopeForParameters(t, fixture, algorithm, actual, contentKey)
	out, err := envelope.Decrypt(fixture.Certificate, fixture.PrivateKey)
	if err == nil {
		t.Fatalf("Decrypt() decrypted an envelope whose declared MGF1 digest was not used, returned %q", out)
	}
	if out != nil {
		t.Errorf("Decrypt() returned %q together with an error", out)
	}
}

// mustMarshalRaw marshals params exactly as Encrypt would write them.
func mustMarshalRaw(t *testing.T, params rsaOAEPParameters) asn1.RawValue {
	t.Helper()
	raw, err := marshalRSAOAEPParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestDecryptWipesContentKey checks the error path does not leave the
// recovered content encryption key in the buffer handed to the symmetric
// decryption. The decryption itself is made to fail so the key is wiped on
// an error path.
func TestDecryptWipesContentKey(t *testing.T) {
	fixture := UnmarshalTestFixture(RSAOAEPSHA256EncryptedTestFixture)

	// Keep a reference to the buffer the RSA operation returns so we can
	// inspect it after Decrypt has scrubbed it.
	var keys [][]byte
	decrypter := &recordingDecrypter{pkey: fixture.PrivateKey, keys: &keys}

	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	params := rsaOAEPParametersForEncryption(crypto.SHA256)
	algorithm := pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmRSAESOAEP, Parameters: mustMarshalRaw(t, params)}

	_, eci := mustEncryptAESCBC(t, []byte("plaintext"), contentKey)
	// Force a deterministic failure in the symmetric decryption, after the
	// content key has been recovered, so the wipe happens on an error path.
	eci.ContentEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	// Produce a real encrypted key so the RSA operation succeeds and the
	// recovered key is the one handed to the symmetric decryption.
	encryptedKey, err := rsa.EncryptOAEP(params.Hash.New(), rand.Reader, &fixture.PrivateKey.PublicKey, contentKey, params.Label)
	if err != nil {
		t.Fatal(err)
	}

	ias, err := cert2issuerAndSerial(fixture.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &PKCS7{raw: envelopedData{
		RecipientInfos: []recipientInfo{{
			IssuerAndSerialNumber:  ias,
			KeyEncryptionAlgorithm: algorithm,
			EncryptedKey:           encryptedKey,
		}},
		EncryptedContentInfo: *eci,
	}}

	if _, err := envelope.Decrypt(fixture.Certificate, decrypter); err == nil {
		t.Fatal("expected the corrupted content decryption to fail")
	}
	if len(keys) != 1 {
		t.Fatalf("recorded %d keys, want 1", len(keys))
	}
	for i, b := range keys[0] {
		if b != 0 {
			t.Fatalf("content key byte %d = %#x after a failed decryption, want it wiped", i, b)
		}
	}
}

// recordingDecrypter performs the RSA decryption and records the buffer it
// returned, so a test can verify it gets wiped.
type recordingDecrypter struct {
	pkey *rsa.PrivateKey
	keys *[][]byte
}

func (d *recordingDecrypter) Public() crypto.PublicKey { return &d.pkey.PublicKey }

func (d *recordingDecrypter) Decrypt(r io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	plaintext, err := d.pkey.Decrypt(r, ciphertext, opts)
	if err == nil {
		*d.keys = append(*d.keys, plaintext)
	}
	return plaintext, err
}

var _ crypto.Decrypter = (*recordingDecrypter)(nil)

// TestGetParametersForKeyEncryptionAlgorithm pins the encoding written by the
// helper that predates the shared contract, ensuring it produces exactly the
// same parameters as the contract Encrypt performs.
func TestGetParametersForKeyEncryptionAlgorithm(t *testing.T) {
	// Non-OAEP algorithms carry no parameters.
	if got, err := getParametersForKeyEncryptionAlgorithm(OIDEncryptionAlgorithmRSA, crypto.SHA256); err != nil || len(got.FullBytes) != 0 {
		t.Errorf("RSA parameters = %x, %v; want empty", got.FullBytes, err)
	}

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		got, err := getParametersForKeyEncryptionAlgorithm(OIDEncryptionAlgorithmRSAESOAEP, hash)
		if err != nil {
			t.Fatalf("%v: %v", hash, err)
		}
		want, err := marshalRSAOAEPParameters(rsaOAEPParametersForEncryption(hash))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.FullBytes, want.FullBytes) {
			t.Errorf("%v: parameters = %x, want %x", hash, got.FullBytes, want.FullBytes)
		}
	}

	// An unsupported digest is an error, not silently SHA-256 or an empty set.
	if _, err := getParametersForKeyEncryptionAlgorithm(OIDEncryptionAlgorithmRSAESOAEP, crypto.MD5); err == nil {
		t.Error("expected an error for an unsupported OAEP digest")
	}
}

// TestMarshalRSAOAEPParametersExplicitFields covers the parameter fields that
// Encrypt never produces itself but the encoder must still describe correctly.
func TestMarshalRSAOAEPParametersExplicitFields(t *testing.T) {
	tests := []struct {
		name   string
		params rsaOAEPParameters
	}{
		{
			name:   "label",
			params: rsaOAEPParameters{Hash: crypto.SHA256, MGFHash: crypto.SHA256, Label: []byte("label")},
		},
		{
			name:   "MGF1 digest different from the OAEP digest",
			params: rsaOAEPParameters{Hash: crypto.SHA256, MGFHash: crypto.SHA1},
		},
		{
			name:   "SHA-1 digest with an explicit SHA-256 MGF1",
			params: rsaOAEPParameters{Hash: crypto.SHA1, MGFHash: crypto.SHA256},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := marshalRSAOAEPParameters(tt.params)
			if err != nil {
				t.Fatalf("marshalRSAOAEPParameters() error = %v", err)
			}
			parsed, err := parseRSAOAEPParameters(raw)
			if err != nil {
				t.Fatalf("cannot parse what was just encoded: %v", err)
			}
			if parsed.Hash != tt.params.Hash || parsed.MGFHash != tt.params.MGFHash || !bytes.Equal(parsed.Label, tt.params.Label) {
				t.Errorf("round trip = %+v, want %+v", parsed, tt.params)
			}
		})
	}

	// An unset digest cannot be encoded; it must not silently become SHA-1.
	if _, err := marshalRSAOAEPParameters(rsaOAEPParameters{MGFHash: crypto.SHA256}); err == nil {
		t.Error("expected an error for parameters without an OAEP digest")
	}
}
