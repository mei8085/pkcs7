package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// createTestCertWithSKID creates a test certificate with an explicit subject
// key identifier and serial number. When issuer is nil the certificate is
// self-signed; when isCA is true the certificate can sign other certificates.
func createTestCertWithSKID(t *testing.T, cn string, serial int64, skid []byte, isCA bool, issuer *certKeyPair) *certKeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		SubjectKeyId:          skid,
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	parent := template
	var parentKey crypto.PrivateKey = key
	if issuer != nil {
		parent = issuer.Certificate
		parentKey = *issuer.PrivateKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey.(crypto.Signer))
	if err != nil {
		t.Fatalf("failed creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed parsing certificate: %v", err)
	}
	var pk crypto.PrivateKey = key
	return &certKeyPair{Certificate: cert, PrivateKey: &pk}
}

func TestParseIdentifier(t *testing.T) {
	ias := issuerAndSerial{
		IssuerName:   asn1.RawValue{FullBytes: []byte{0x30, 0x03, 0x31, 0x01, 0x00}},
		SerialNumber: big.NewInt(42),
	}
	iasDER, err := asn1.Marshal(ias)
	if err != nil {
		t.Fatalf("failed marshaling issuerAndSerial: %v", err)
	}

	t.Run("missing", func(t *testing.T) {
		if _, err := parseIdentifier(asn1.RawValue{}); !errors.Is(err, ErrMissingIdentifier) {
			t.Fatalf("expected ErrMissingIdentifier, got %v", err)
		}
	})

	t.Run("issuerAndSerialNumber", func(t *testing.T) {
		id, err := parseIdentifier(asn1.RawValue{FullBytes: iasDER})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id.kind != identifierKindIssuerAndSerial {
			t.Fatalf("expected issuerAndSerialNumber identifier, got kind %d", id.kind)
		}
		if id.ias.SerialNumber.Cmp(big.NewInt(42)) != 0 {
			t.Fatalf("expected serial 42, got %v", id.ias.SerialNumber)
		}
	})

	t.Run("subjectKeyIdentifier", func(t *testing.T) {
		skid := []byte{0x01, 0x02, 0x03, 0x04}
		raw, err := marshalSKIDIdentifier(skid)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		der, err := asn1.Marshal(raw)
		if err != nil {
			t.Fatalf("failed marshaling SKID identifier: %v", err)
		}
		var parsed asn1.RawValue
		if _, err := asn1.Unmarshal(der, &parsed); err != nil {
			t.Fatalf("failed unmarshaling SKID identifier: %v", err)
		}
		id, err := parseIdentifier(parsed)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id.kind != identifierKindSubjectKeyIdentifier {
			t.Fatalf("expected subjectKeyIdentifier, got kind %d", id.kind)
		}
		if !bytes.Equal(id.skid, skid) {
			t.Fatalf("expected SKID %x, got %x", skid, id.skid)
		}
	})

	t.Run("malformedIssuerAndSerialNumber", func(t *testing.T) {
		// SEQUENCE containing an OCTET STRING instead of issuerAndSerialNumber
		bad := []byte{0x30, 0x03, 0x04, 0x01, 0xff}
		if _, err := parseIdentifier(asn1.RawValue{FullBytes: bad}); !errors.Is(err, ErrMalformedIdentifier) {
			t.Fatalf("expected ErrMalformedIdentifier, got %v", err)
		}
	})

	t.Run("emptySubjectKeyIdentifier", func(t *testing.T) {
		// context-specific [0] primitive with empty content
		bad := []byte{0x80, 0x00}
		if _, err := parseIdentifier(asn1.RawValue{FullBytes: bad}); !errors.Is(err, ErrMalformedIdentifier) {
			t.Fatalf("expected ErrMalformedIdentifier, got %v", err)
		}
	})

	t.Run("unexpectedTag", func(t *testing.T) {
		// context-specific [1] is not a valid identifier alternative
		bad := []byte{0x81, 0x01, 0x00}
		if _, err := parseIdentifier(asn1.RawValue{FullBytes: bad}); !errors.Is(err, ErrMalformedIdentifier) {
			t.Fatalf("expected ErrMalformedIdentifier, got %v", err)
		}
	})

	t.Run("marshalEmptySKID", func(t *testing.T) {
		if _, err := marshalSKIDIdentifier(nil); !errors.Is(err, ErrNoSubjectKeyIdentifier) {
			t.Fatalf("expected ErrNoSubjectKeyIdentifier, got %v", err)
		}
	})
}

func TestSelectCertificate(t *testing.T) {
	skidA := []byte("key-identifier-a0001")
	skidB := []byte("key-identifier-b0002")
	certA := createTestCertWithSKID(t, "cert-a", 1, skidA, false, nil)
	certB := createTestCertWithSKID(t, "cert-b", 2, skidB, false, nil)
	// certA2 is a distinct certificate (different serial/key) reusing cert A's SKID
	certA2 := createTestCertWithSKID(t, "cert-a-duplicate", 3, skidA, false, nil)

	t.Run("match", func(t *testing.T) {
		id := identifier{kind: identifierKindSubjectKeyIdentifier, skid: skidA}
		cert, err := selectCertificate([]*x509.Certificate{certB.Certificate, certA.Certificate}, id)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert != certA.Certificate {
			t.Fatal("expected cert A to be selected")
		}
	})

	t.Run("noMatch", func(t *testing.T) {
		id := identifier{kind: identifierKindSubjectKeyIdentifier, skid: []byte("no-such-key-id-0000")}
		cert, err := selectCertificate([]*x509.Certificate{certA.Certificate, certB.Certificate}, id)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert != nil {
			t.Fatal("expected no certificate to be selected")
		}
	})

	t.Run("certWithoutSKIDNeverMatches", func(t *testing.T) {
		noSKID := createTestCertWithSKID(t, "no-skid", 4, nil, false, nil)
		id := identifier{kind: identifierKindSubjectKeyIdentifier, skid: skidA}
		cert, err := selectCertificate([]*x509.Certificate{noSKID.Certificate}, id)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert != nil {
			t.Fatal("certificate without SubjectKeyId must not match a SKID identifier")
		}
	})

	t.Run("duplicateIdenticalCertificates", func(t *testing.T) {
		id := identifier{kind: identifierKindSubjectKeyIdentifier, skid: skidA}
		cert, err := selectCertificate([]*x509.Certificate{certA.Certificate, certA.Certificate}, id)
		if err != nil {
			t.Fatalf("identical certificates must not be ambiguous: %v", err)
		}
		if cert != certA.Certificate {
			t.Fatal("expected cert A to be selected")
		}
	})

	t.Run("duplicateDistinctCertificates", func(t *testing.T) {
		id := identifier{kind: identifierKindSubjectKeyIdentifier, skid: skidA}
		if _, err := selectCertificate([]*x509.Certificate{certA.Certificate, certA2.Certificate}, id); !errors.Is(err, ErrDuplicateIdentifier) {
			t.Fatalf("expected ErrDuplicateIdentifier, got %v", err)
		}
	})
}

func TestSignAndVerifyWithSKID(t *testing.T) {
	skid := []byte("signer-key-id-000001")
	root := createTestCertWithSKID(t, "PKCS7 Test Root CA", 1, []byte("root-key-id-00000001"), true, nil)
	signer := createTestCertWithSKID(t, "PKCS7 Test Signer Cert", 2, skid, false, root)
	truststore := x509.NewCertPool()
	truststore.AddCert(root.Certificate)

	content := []byte("Hello SKID")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}
	config := SignerInfoConfig{UseSubjectKeyIdentifier: true}
	if err := toBeSigned.AddSignerChain(signer.Certificate, *signer.PrivateKey, []*x509.Certificate{root.Certificate}, config); err != nil {
		t.Fatalf("failed adding signer: %v", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("failed finishing signed data: %v", err)
	}

	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("failed parsing signed data: %v", err)
	}
	if len(p7.Signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(p7.Signers))
	}
	if p7.Signers[0].Version != 3 {
		t.Fatalf("expected SignerInfo version 3, got %d", p7.Signers[0].Version)
	}
	if sd, ok := p7.raw.(signedData); !ok || sd.Version != 3 {
		t.Fatalf("expected SignedData version 3, got %+v", p7.raw)
	}
	id, err := parseIdentifier(p7.Signers[0].SignerIdentifier)
	if err != nil {
		t.Fatalf("failed parsing signer identifier: %v", err)
	}
	if id.kind != identifierKindSubjectKeyIdentifier {
		t.Fatalf("expected subjectKeyIdentifier, got kind %d", id.kind)
	}
	if !bytes.Equal(id.skid, skid) {
		t.Fatalf("expected SKID %x, got %x", skid, id.skid)
	}
	if err := p7.VerifyWithChain(truststore); err != nil {
		t.Fatalf("failed verifying SKID signed data: %v", err)
	}
	if only := p7.GetOnlySigner(); only == nil || !bytes.Equal(only.Raw, signer.Certificate.Raw) {
		t.Fatal("GetOnlySigner did not return the signer certificate")
	}
}

func TestSignWithoutAttrWithSKID(t *testing.T) {
	skid := []byte("signer-key-id-000002")
	signer := createTestCertWithSKID(t, "PKCS7 Test Signer Cert", 10, skid, false, nil)

	toBeSigned, err := NewSignedData([]byte("Hello SKID"))
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}
	config := SignerInfoConfig{UseSubjectKeyIdentifier: true}
	if err := toBeSigned.SignWithoutAttr(signer.Certificate, *signer.PrivateKey, config); err != nil {
		t.Fatalf("failed signing without attributes: %v", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("failed finishing signed data: %v", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("failed parsing signed data: %v", err)
	}
	if p7.Signers[0].Version != 3 {
		t.Fatalf("expected SignerInfo version 3, got %d", p7.Signers[0].Version)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("failed verifying SKID signed data: %v", err)
	}
}

func TestSignWithSKIDMissingOnCertificate(t *testing.T) {
	signer := createTestCertWithSKID(t, "PKCS7 Test Signer Cert", 20, nil, false, nil)
	toBeSigned, err := NewSignedData([]byte("Hello SKID"))
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}
	config := SignerInfoConfig{UseSubjectKeyIdentifier: true}
	if err := toBeSigned.AddSigner(signer.Certificate, *signer.PrivateKey, config); !errors.Is(err, ErrNoSubjectKeyIdentifier) {
		t.Fatalf("expected ErrNoSubjectKeyIdentifier, got %v", err)
	}
}

func signWithSKIDForTest(t *testing.T, signer *certKeyPair, parents []*x509.Certificate) *PKCS7 {
	t.Helper()
	toBeSigned, err := NewSignedData([]byte("Hello SKID"))
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}
	config := SignerInfoConfig{UseSubjectKeyIdentifier: true}
	if err := toBeSigned.AddSignerChain(signer.Certificate, *signer.PrivateKey, parents, config); err != nil {
		t.Fatalf("failed adding signer: %v", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("failed finishing signed data: %v", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("failed parsing signed data: %v", err)
	}
	return p7
}

func TestVerifySKIDFailureModes(t *testing.T) {
	skid := []byte("signer-key-id-000003")
	signer := createTestCertWithSKID(t, "PKCS7 Test Signer Cert", 30, skid, false, nil)

	t.Run("noCertificate", func(t *testing.T) {
		p7 := signWithSKIDForTest(t, signer, nil)
		p7.Certificates = nil
		if err := p7.Verify(); !errors.Is(err, ErrNoCertificateForSigner) {
			t.Fatalf("expected ErrNoCertificateForSigner, got %v", err)
		}
	})

	t.Run("noFallbackToIssuerAndSerial", func(t *testing.T) {
		p7 := signWithSKIDForTest(t, signer, nil)
		// A certificate with the same issuer name and serial number but a
		// different SKID must not be matched for a SKID-identified signer.
		imposter := createTestCertWithSKID(t, "PKCS7 Test Signer Cert", 30, []byte("another-key-id-00003"), false, nil)
		imposter.Certificate.RawIssuer = signer.Certificate.RawIssuer
		p7.Certificates = []*x509.Certificate{imposter.Certificate}
		if err := p7.Verify(); !errors.Is(err, ErrNoCertificateForSigner) {
			t.Fatalf("expected ErrNoCertificateForSigner, got %v", err)
		}
	})

	t.Run("duplicateIdentifier", func(t *testing.T) {
		p7 := signWithSKIDForTest(t, signer, nil)
		duplicate := createTestCertWithSKID(t, "PKCS7 Duplicate Signer Cert", 31, skid, false, nil)
		p7.Certificates = append(p7.Certificates, duplicate.Certificate)
		if err := p7.Verify(); !errors.Is(err, ErrDuplicateIdentifier) {
			t.Fatalf("expected ErrDuplicateIdentifier, got %v", err)
		}
	})

	t.Run("missingIdentifier", func(t *testing.T) {
		p7 := signWithSKIDForTest(t, signer, nil)
		p7.Signers[0].SignerIdentifier = asn1.RawValue{}
		if err := p7.Verify(); !errors.Is(err, ErrMissingIdentifier) {
			t.Fatalf("expected ErrMissingIdentifier, got %v", err)
		}
	})

	t.Run("malformedIdentifier", func(t *testing.T) {
		p7 := signWithSKIDForTest(t, signer, nil)
		// context-specific [0] with empty content
		p7.Signers[0].SignerIdentifier = asn1.RawValue{FullBytes: []byte{0x80, 0x00}}
		if err := p7.Verify(); !errors.Is(err, ErrMalformedIdentifier) {
			t.Fatalf("expected ErrMalformedIdentifier, got %v", err)
		}
	})
}

func TestEncryptAndDecryptWithSKID(t *testing.T) {
	skid := []byte("recipient-key-id-0001")
	recipient := createTestCertWithSKID(t, "PKCS7 Test Recipient", 40, skid, false, nil)
	content := []byte("Hello SKID Envelope")

	encrypted, err := EncryptWithSKID(content, []*x509.Certificate{recipient.Certificate})
	if err != nil {
		t.Fatalf("failed encrypting: %v", err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatalf("failed parsing enveloped data: %v", err)
	}
	ed, ok := p7.raw.(envelopedData)
	if !ok {
		t.Fatalf("expected envelopedData, got %T", p7.raw)
	}
	if ed.Version != 2 {
		t.Fatalf("expected EnvelopedData version 2, got %d", ed.Version)
	}
	if len(ed.RecipientInfos) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(ed.RecipientInfos))
	}
	if ed.RecipientInfos[0].Version != 2 {
		t.Fatalf("expected RecipientInfo version 2, got %d", ed.RecipientInfos[0].Version)
	}
	id, err := parseIdentifier(ed.RecipientInfos[0].RecipientIdentifier)
	if err != nil {
		t.Fatalf("failed parsing recipient identifier: %v", err)
	}
	if id.kind != identifierKindSubjectKeyIdentifier {
		t.Fatalf("expected subjectKeyIdentifier, got kind %d", id.kind)
	}
	if !bytes.Equal(id.skid, skid) {
		t.Fatalf("expected SKID %x, got %x", skid, id.skid)
	}

	decrypted, err := p7.Decrypt(recipient.Certificate, *recipient.PrivateKey)
	if err != nil {
		t.Fatalf("failed decrypting: %v", err)
	}
	if !bytes.Equal(decrypted, content) {
		t.Fatalf("expected decrypted content %q, got %q", content, decrypted)
	}
}

func TestEncryptWithSKIDMissingOnCertificate(t *testing.T) {
	recipient := createTestCertWithSKID(t, "PKCS7 Test Recipient", 50, nil, false, nil)
	if _, err := EncryptWithSKID([]byte("data"), []*x509.Certificate{recipient.Certificate}); !errors.Is(err, ErrNoSubjectKeyIdentifier) {
		t.Fatalf("expected ErrNoSubjectKeyIdentifier, got %v", err)
	}
}

func TestDecryptSKIDFailureModes(t *testing.T) {
	skid := []byte("recipient-key-id-0002")
	recipient := createTestCertWithSKID(t, "PKCS7 Test Recipient", 60, skid, false, nil)
	content := []byte("Hello SKID Envelope")

	encrypted, err := EncryptWithSKID(content, []*x509.Certificate{recipient.Certificate})
	if err != nil {
		t.Fatalf("failed encrypting: %v", err)
	}

	t.Run("wrongCertificate", func(t *testing.T) {
		p7, err := Parse(encrypted)
		if err != nil {
			t.Fatalf("failed parsing enveloped data: %v", err)
		}
		other := createTestCertWithSKID(t, "PKCS7 Other Recipient", 61, []byte("recipient-key-id-0003"), false, nil)
		if _, err := p7.Decrypt(other.Certificate, *other.PrivateKey); !errors.Is(err, ErrNoCertificateForRecipient) {
			t.Fatalf("expected ErrNoCertificateForRecipient, got %v", err)
		}
	})

	t.Run("malformedRecipientIdentifier", func(t *testing.T) {
		p7, err := Parse(encrypted)
		if err != nil {
			t.Fatalf("failed parsing enveloped data: %v", err)
		}
		ed := p7.raw.(envelopedData)
		ed.RecipientInfos[0].RecipientIdentifier = asn1.RawValue{FullBytes: []byte{0x80, 0x00}}
		p7.raw = ed
		if _, err := p7.Decrypt(recipient.Certificate, *recipient.PrivateKey); !errors.Is(err, ErrNoCertificateForRecipient) {
			t.Fatalf("expected ErrNoCertificateForRecipient, got %v", err)
		}
	})
}

func TestIssuerAndSerialNumberIdentifierStillWorks(t *testing.T) {
	root := createTestCertWithSKID(t, "PKCS7 Test Root CA", 70, []byte("root-key-id-00000070"), true, nil)
	signer := createTestCertWithSKID(t, "PKCS7 Test Signer Cert", 71, []byte("signer-key-id-000071"), false, root)
	truststore := x509.NewCertPool()
	truststore.AddCert(root.Certificate)

	toBeSigned, err := NewSignedData([]byte("Hello IAS"))
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}
	if err := toBeSigned.AddSignerChain(signer.Certificate, *signer.PrivateKey, []*x509.Certificate{root.Certificate}, SignerInfoConfig{}); err != nil {
		t.Fatalf("failed adding signer: %v", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("failed finishing signed data: %v", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("failed parsing signed data: %v", err)
	}
	if p7.Signers[0].Version != 1 {
		t.Fatalf("expected SignerInfo version 1, got %d", p7.Signers[0].Version)
	}
	id, err := parseIdentifier(p7.Signers[0].SignerIdentifier)
	if err != nil {
		t.Fatalf("failed parsing signer identifier: %v", err)
	}
	if id.kind != identifierKindIssuerAndSerial {
		t.Fatalf("expected issuerAndSerialNumber, got kind %d", id.kind)
	}
	if err := p7.VerifyWithChain(truststore); err != nil {
		t.Fatalf("failed verifying issuerAndSerialNumber signed data: %v", err)
	}

	encrypted, err := Encrypt([]byte("Hello IAS Envelope"), []*x509.Certificate{signer.Certificate})
	if err != nil {
		t.Fatalf("failed encrypting: %v", err)
	}
	p7, err = Parse(encrypted)
	if err != nil {
		t.Fatalf("failed parsing enveloped data: %v", err)
	}
	ed, ok := p7.raw.(envelopedData)
	if !ok {
		t.Fatalf("expected envelopedData, got %T", p7.raw)
	}
	if ed.RecipientInfos[0].Version != 0 {
		t.Fatalf("expected RecipientInfo version 0, got %d", ed.RecipientInfos[0].Version)
	}
	id, err = parseIdentifier(ed.RecipientInfos[0].RecipientIdentifier)
	if err != nil {
		t.Fatalf("failed parsing recipient identifier: %v", err)
	}
	if id.kind != identifierKindIssuerAndSerial {
		t.Fatalf("expected issuerAndSerialNumber, got kind %d", id.kind)
	}
	decrypted, err := p7.Decrypt(signer.Certificate, *signer.PrivateKey)
	if err != nil {
		t.Fatalf("failed decrypting: %v", err)
	}
	if !bytes.Equal(decrypted, []byte("Hello IAS Envelope")) {
		t.Fatalf("unexpected decrypted content %q", decrypted)
	}
}
