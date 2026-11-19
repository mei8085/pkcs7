package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestEncrypt(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128CBC,
		EncryptionAlgorithmAES256CBC,
		EncryptionAlgorithmAES128GCM,
		EncryptionAlgorithmAES256GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
	}
	for _, mode := range modes {
		for _, sigalg := range sigalgs {
			ContentEncryptionAlgorithm = mode

			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptUsingPSK(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128GCM,
	}

	for _, mode := range modes {
		ContentEncryptionAlgorithm = mode
		plaintext := []byte("Hello Secret World!")
		var key []byte

		switch mode {
		case EncryptionAlgorithmDESCBC:
			key = []byte("64BitKey")
		case EncryptionAlgorithmAES128GCM:
			key = []byte("128BitKey4AESGCM")
		}
		ciphertext, err := EncryptUsingPSK(plaintext, key)
		if err != nil {
			t.Fatal(err)
		}

		p7, _ := Parse(ciphertext)
		result, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		Original  []byte
		Expected  []byte
		BlockSize int
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8},
	}
	for _, test := range tests {
		padded, err := pad(test.Original, test.BlockSize)
		if err != nil {
			t.Errorf("pad encountered error: %s", err)
			continue
		}
		if !bytes.Equal(test.Expected, padded) {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.Expected, padded)
		}
	}
}

func Test_marshalAndParseRSAOAEPParameters(t *testing.T) {
	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{name: "sha1", hash: crypto.SHA1},
		{name: "sha224", hash: crypto.SHA224},
		{name: "sha256", hash: crypto.SHA256},
		{name: "sha384", hash: crypto.SHA384},
		{name: "sha512", hash: crypto.SHA512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The parameters that are written must describe the operation
			// that encryption performs: the same digest for OAEP and MGF1.
			requested := rsaOAEPParametersForEncryption(tt.hash)
			got, err := marshalRSAOAEPParameters(requested)
			if err != nil {
				t.Fatalf("marshalRSAOAEPParameters() error = %v", err)
			}

			// test if the reverse operation results in the same contract
			alg := pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmRSAESOAEP, Parameters: got}
			parsed, err := getOAEPParametersForKeyEncryptionAlgorithm(alg)
			if err != nil {
				t.Fatalf("getOAEPParametersForKeyEncryptionAlgorithm() error = %v", err)
			}
			if parsed.Hash != requested.Hash {
				t.Errorf("parsed hash = %v, want %v", parsed.Hash, requested.Hash)
			}
			if parsed.MGFHash != requested.MGFHash {
				t.Errorf("parsed MGF1 hash = %v, want %v", parsed.MGFHash, requested.MGFHash)
			}
			if !bytes.Equal(parsed.Label, requested.Label) {
				t.Errorf("parsed label = %x, want %x", parsed.Label, requested.Label)
			}

			// The declared parameters must agree with the operation that
			// Encrypt actually performs.
			declaredHash, err := getHashFuncForKeyEncryptionAlgorithm(alg)
			if err != nil {
				t.Fatalf("getHashFuncForKeyEncryptionAlgorithm() error = %v", err)
			}
			if declaredHash != tt.hash {
				t.Errorf("getHashFuncForKeyEncryptionAlgorithm() = %v, want %v", declaredHash, tt.hash)
			}
		})
	}
}

func TestMarshalRSAOAEPParametersEncoding(t *testing.T) {
	// SHA-1 is the default for both the digest and MGF1, so the canonical
	// encoding is the empty SEQUENCE, exactly as OpenSSL emits it.
	params, err := marshalRSAOAEPParameters(rsaOAEPParametersForEncryption(crypto.SHA1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(params.FullBytes, []byte{0x30, 0x00}) {
		t.Errorf("SHA-1 parameters = %x, want 3000", params.FullBytes)
	}

	// Any other digest must be written out, both as hashAlgorithm and as the
	// digest used by the MGF1 mask generation function. Omitting the latter
	// would declare the MGF1-SHA-1 default while computing MGF1 with the
	// selected digest.
	for _, hash := range []crypto.Hash{crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		raw, err := marshalRSAOAEPParameters(rsaOAEPParametersForEncryption(hash))
		if err != nil {
			t.Fatalf("%v: %v", hash, err)
		}
		var decoded rsaOAEPAlgorithmParameters
		rest, err := asn1.Unmarshal(raw.FullBytes, &decoded)
		if err != nil {
			t.Fatalf("%v: %v", hash, err)
		}
		if len(rest) != 0 {
			t.Fatalf("%v: trailing data", hash)
		}
		wantOID, _ := oidForHash(hash)
		if !decoded.HashFunc.Algorithm.Equal(wantOID) {
			t.Errorf("%v: hashAlgorithm = %v, want %v", hash, decoded.HashFunc.Algorithm, wantOID)
		}
		if !decoded.MaskGenFunc.Algorithm.Equal(OIDMaskGenAlgorithmMGF1) {
			t.Errorf("%v: maskGenAlgorithm = %v, want MGF1", hash, decoded.MaskGenFunc.Algorithm)
		}
		var mgfHash pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(decoded.MaskGenFunc.Parameters.FullBytes, &mgfHash); err != nil {
			t.Fatalf("%v: cannot parse MGF1 parameters: %v", hash, err)
		}
		if !mgfHash.Algorithm.Equal(wantOID) {
			t.Errorf("%v: MGF1 digest = %v, want %v", hash, mgfHash.Algorithm, wantOID)
		}
	}
}

func Test_marshalEncryptedContent(t *testing.T) {
	content := []byte{}
	got := marshalEncryptedContent(content)

	expected := asn1.RawValue{Class: 2, Tag: 0, IsCompound: false, Bytes: []byte{}, FullBytes: nil}
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("marshalEncryptedContent() = %v, want %v", got, expected)
	}

	content = []byte{34, 165, 121, 103, 15, 109, 119, 147, 39, 236, 212, 103, 143, 164, 172, 22}
	got = marshalEncryptedContent(content)
	expected = asn1.RawValue{Class: 2, Tag: 0, IsCompound: false, Bytes: []byte{34, 165, 121, 103, 15, 109, 119, 147, 39, 236, 212, 103, 143, 164, 172, 22}, FullBytes: nil}
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("marshalEncryptedContent() = %v, want %v", got, expected)
	}
}

func TestEncryptAndDecryptWithOpenSSL(t *testing.T) {
	tf := UnmarshalTestFixture(RSAOAEPSHA256EncryptedTestFixture) // use existing fixture with cert + key

	content := []byte("this is the content")
	recipients := []*x509.Certificate{tf.Certificate}
	currentAlgorithm := ContentEncryptionAlgorithm
	ContentEncryptionAlgorithm = EncryptionAlgorithmAES256CBC
	defer func() {
		ContentEncryptionAlgorithm = currentAlgorithm
	}()
	encryptedContent, err := Encrypt(content, recipients)
	if err != nil {
		t.Fatal(err)
	}

	contentFile, err := ioutil.TempFile("", "content")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(contentFile.Name())

	err = pem.Encode(contentFile, &pem.Block{Type: "PKCS7", Bytes: encryptedContent})
	if err != nil {
		t.Fatal(err)
	}
	contentFile.Close()

	recipientFile, err := ioutil.TempFile("", "content")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(recipientFile.Name())

	err = pem.Encode(recipientFile, &pem.Block{Type: "CERTIFICATE", Bytes: tf.Certificate.Raw})
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := x509.MarshalPKCS8PrivateKey(tf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(recipientFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	recipientFile.Close()

	// call openssl to decrypt the content
	opensslCMD := exec.Command("openssl", "cms", "-decrypt",
		"-inform", "pem",
		"-in", contentFile.Name(),
		"-recip", recipientFile.Name(),
	)
	out, err := opensslCMD.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl command failed with %s: %s", err, out)
	}

	if !bytes.Equal(content, out) {
		t.Errorf("EncryptAndDecryptWithOpenSSL() = %v, want %v", out, content)
	}
}

// TestEncryptDecryptOAEPRoundTrip exercises the full contract for every
// supported digest: the envelope written by Encrypt must be decryptable by
// Decrypt, and the parameters it carries must match the digest that was
// requested.
func TestEncryptDecryptOAEPRoundTrip(t *testing.T) {
	fixture := UnmarshalTestFixture(RSAOAEPSHA256EncryptedTestFixture)
	plaintext := []byte("Hello Secret World!")

	currentAlgorithm := ContentEncryptionAlgorithm
	currentKeyAlgorithm := KeyEncryptionAlgorithm
	currentHash := KeyEncryptionHash
	defer func() {
		ContentEncryptionAlgorithm = currentAlgorithm
		KeyEncryptionAlgorithm = currentKeyAlgorithm
		KeyEncryptionHash = currentHash
	}()

	ContentEncryptionAlgorithm = EncryptionAlgorithmAES256CBC
	KeyEncryptionAlgorithm = OIDEncryptionAlgorithmRSAESOAEP

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run(hash.String(), func(t *testing.T) {
			KeyEncryptionHash = hash

			encrypted, err := Encrypt(plaintext, []*x509.Certificate{fixture.Certificate})
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			// The parameters in the envelope must resolve to the digest
			// that was requested, both as the OAEP digest and (because
			// that is what Encrypt performs) as the MGF1 digest.
			ed := p7.raw.(envelopedData)
			if len(ed.RecipientInfos) != 1 {
				t.Fatalf("got %d recipients, want 1", len(ed.RecipientInfos))
			}
			params, err := getOAEPParametersForKeyEncryptionAlgorithm(ed.RecipientInfos[0].KeyEncryptionAlgorithm)
			if err != nil {
				t.Fatalf("envelope carried unusable parameters: %v", err)
			}
			if params.Hash != hash {
				t.Errorf("declared digest = %v, want %v", params.Hash, hash)
			}
			if params.MGFHash != hash {
				t.Errorf("declared MGF1 digest = %v, want %v (the digest Encrypt uses)", params.MGFHash, hash)
			}
			if len(params.Label) != 0 {
				t.Errorf("declared label = %x, want empty", params.Label)
			}

			content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if !bytes.Equal(content, plaintext) {
				t.Errorf("decrypted = %q, want %q", content, plaintext)
			}
		})
	}
}

// TestEncryptOAEPInteropWithOpenSSL checks that OpenSSL accepts the envelope
// this package writes, for the default parameters and for explicit SHA-256
// parameters. This is the interoperability half of the contract: a declared
// parameter set must be one other implementations also honour.
func TestEncryptOAEPInteropWithOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	fixture := UnmarshalTestFixture(RSAOAEPSHA256EncryptedTestFixture)
	content := []byte("openssl interop content")

	currentAlgorithm := ContentEncryptionAlgorithm
	currentKeyAlgorithm := KeyEncryptionAlgorithm
	currentHash := KeyEncryptionHash
	defer func() {
		ContentEncryptionAlgorithm = currentAlgorithm
		KeyEncryptionAlgorithm = currentKeyAlgorithm
		KeyEncryptionHash = currentHash
	}()
	ContentEncryptionAlgorithm = EncryptionAlgorithmAES256CBC
	KeyEncryptionAlgorithm = OIDEncryptionAlgorithmRSAESOAEP

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA512} {
		t.Run(hash.String(), func(t *testing.T) {
			KeyEncryptionHash = hash
			encrypted, err := Encrypt(content, []*x509.Certificate{fixture.Certificate})
			if err != nil {
				t.Fatal(err)
			}

			contentFile, err := ioutil.TempFile("", "content")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(contentFile.Name())
			if err := pem.Encode(contentFile, &pem.Block{Type: "PKCS7", Bytes: encrypted}); err != nil {
				t.Fatal(err)
			}
			contentFile.Close()

			recipientFile, err := ioutil.TempFile("", "recipient")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(recipientFile.Name())
			if err := pem.Encode(recipientFile, &pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate.Raw}); err != nil {
				t.Fatal(err)
			}
			privateKey, err := x509.MarshalPKCS8PrivateKey(fixture.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := pem.Encode(recipientFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}); err != nil {
				t.Fatal(err)
			}
			recipientFile.Close()

			out, err := exec.Command("openssl", "cms", "-decrypt",
				"-inform", "pem",
				"-in", contentFile.Name(),
				"-recip", recipientFile.Name(),
			).CombinedOutput()
			if err != nil {
				t.Fatalf("openssl failed to decrypt an envelope with declared %v parameters: %s: %s", hash, err, out)
			}
			if !bytes.Equal(out, content) {
				t.Errorf("openssl decrypted %q, want %q", out, content)
			}
		})
	}
}
