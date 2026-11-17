package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
)

// TestDecryptIndistinguishableFailures verifies that invalid RSAES-PKCS1-v1_5
// padding, a content key of the wrong length and undecryptable content all
// result in the same error, so that no padding oracle is exposed.
func TestDecryptIndistinguishableFailures(t *testing.T) {
	fixture := UnmarshalTestFixture(RSAPKCS1v15EncryptedTestFixture)
	cert := fixture.Certificate
	priv := fixture.PrivateKey

	const contentKeyLen = 32 // AES-256-CBC
	contentKey := make([]byte, contentKeyLen)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	_, eci := mustEncryptAESCBC(t, []byte("This is a test"), contentKey)

	// The ciphertext is the RSA public-key operation on an encoded message.
	// Constructing the encoded message directly makes each case
	// deterministic, instead of relying on random ciphertexts.
	badPadding := rsaCiphertextForEM(t, priv, encodePKCS1v15EM(t, priv, 0x01, contentKey))
	wrongKeyLen := rsaCiphertextForEM(t, priv, encodePKCS1v15EM(t, priv, 0x02, contentKey[:16]))
	validKey := rsaCiphertextForEM(t, priv, encodePKCS1v15EM(t, priv, 0x02, contentKey))
	tooShort := []byte{0x00, 0x01, 0x02}

	corruptedContent := *eci
	corruptedContent.EncryptedContent = asn1.RawValue{Class: 2, Bytes: cbcCiphertextForBlock(t, make([]byte, contentKeyLen), eci.ContentEncryptionAlgorithm.Parameters.Bytes, make([]byte, 16))}

	tests := []struct {
		name    string
		alg     asn1.ObjectIdentifier
		key     []byte
		content encryptedContentInfo
		oaep    bool
	}{
		{name: "invalid RSA padding", alg: OIDEncryptionAlgorithmRSA, key: badPadding, content: *eci},
		{name: "valid padding, wrong content key length", alg: OIDEncryptionAlgorithmRSA, key: wrongKeyLen, content: *eci},
		{name: "RSA ciphertext of the wrong size", alg: OIDEncryptionAlgorithmRSA, key: tooShort, content: *eci},
		{name: "valid key, corrupted content", alg: OIDEncryptionAlgorithmRSA, key: validKey, content: corruptedContent},
		{name: "OAEP content key failure", alg: OIDEncryptionAlgorithmRSAESOAEP, key: badPadding, content: *eci, oaep: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p7 := envelopeForKeyEncryptionAlgorithm(t, cert, tt.alg, tt.key, tt.content)
			if tt.oaep {
				params, err := getParametersForKeyEncryptionAlgorithm(OIDEncryptionAlgorithmRSAESOAEP, crypto.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				p7.raw.(envelopedData).RecipientInfos[0].KeyEncryptionAlgorithm.Parameters = params
			}
			out, err := p7.Decrypt(cert, priv)
			if err == nil {
				t.Fatalf("expected an error, got plaintext %q", out)
			}
			if !errors.Is(err, ErrDecryption) {
				t.Fatalf("expected ErrDecryption, got %v", err)
			}
			if err.Error() != ErrDecryption.Error() {
				t.Fatalf("expected the error to be indistinguishable from ErrDecryption, got %q", err)
			}
			if out != nil {
				t.Fatalf("expected no plaintext on failure, got %q", out)
			}
		})
	}
}

// TestDecryptPKCS1v15ContentKeyValid verifies that a validly wrapped content
// key of the expected length still decrypts the content.
func TestDecryptPKCS1v15ContentKeyValid(t *testing.T) {
	fixture := UnmarshalTestFixture(RSAPKCS1v15EncryptedTestFixture)
	cert := fixture.Certificate
	priv := fixture.PrivateKey

	plaintext := []byte("This is a test")
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	_, eci := mustEncryptAESCBC(t, plaintext, contentKey)

	for _, encryptedKey := range [][]byte{
		rsaCiphertextForEM(t, priv, encodePKCS1v15EM(t, priv, 0x02, contentKey)),
		mustEncryptPKCS1v15(t, &priv.PublicKey, contentKey),
	} {
		p7 := envelopeForKeyEncryptionAlgorithm(t, cert, OIDEncryptionAlgorithmRSA, encryptedKey, *eci)
		out, err := p7.Decrypt(cert, priv)
		if err != nil {
			t.Fatalf("cannot decrypt: %v", err)
		}
		if !bytes.Equal(out, plaintext) {
			t.Fatalf("unexpected plaintext: got %q, want %q", out, plaintext)
		}
	}
}

// TestDecryptContentKeyLengthEnforced verifies that every content encryption
// algorithm rejects content keys of the wrong length.
func TestDecryptContentKeyLengthEnforced(t *testing.T) {
	algs := []struct {
		name   string
		oid    asn1.ObjectIdentifier
		keyLen int
	}{
		{name: "DES-CBC", oid: OIDEncryptionAlgorithmDESCBC, keyLen: 8},
		{name: "AES-128-CBC", oid: OIDEncryptionAlgorithmAES128CBC, keyLen: 16},
		{name: "AES-256-CBC", oid: OIDEncryptionAlgorithmAES256CBC, keyLen: 32},
	}
	for _, alg := range algs {
		t.Run(alg.name, func(t *testing.T) {
			eci := encryptedContentInfo{
				ContentType:                OIDData,
				ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: alg.oid, Parameters: asn1.RawValue{Tag: 4, Bytes: make([]byte, 8)}},
			}
			for _, keyLen := range []int{0, alg.keyLen - 1, alg.keyLen + 1, alg.keyLen * 2} {
				if _, err := eci.decrypt(make([]byte, keyLen)); err == nil {
					t.Fatalf("expected an error for key length %d with %s", keyLen, alg.name)
				}
			}
		})
	}
}

// TestDecryptMalformedInputDoesNotPanic verifies that malformed encrypted
// content results in an error instead of a crash.
func TestDecryptMalformedInputDoesNotPanic(t *testing.T) {
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, block.BlockSize())

	tests := []struct {
		name    string
		content encryptedContentInfo
	}{
		{
			name: "truncated CBC ciphertext",
			content: encryptedContentInfo{
				ContentType:                OIDData,
				ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmAES256CBC, Parameters: asn1.RawValue{Tag: 4, Bytes: iv}},
				EncryptedContent:           asn1.RawValue{Class: 2, Bytes: []byte{0x01, 0x02, 0x03}},
			},
		},
		{
			name: "empty CBC ciphertext",
			content: encryptedContentInfo{
				ContentType:                OIDData,
				ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmAES256CBC, Parameters: asn1.RawValue{Tag: 4, Bytes: iv}},
				EncryptedContent:           asn1.RawValue{Class: 2},
			},
		},
		{
			name: "malformed IV",
			content: encryptedContentInfo{
				ContentType:                OIDData,
				ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmAES256CBC, Parameters: asn1.RawValue{Tag: 4, Bytes: []byte{0x01}}},
				EncryptedContent:           asn1.RawValue{Class: 2, Bytes: make([]byte, block.BlockSize())},
			},
		},
		{
			name: "malformed GCM parameters",
			content: encryptedContentInfo{
				ContentType:                OIDData,
				ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmAES256GCM, Parameters: asn1.RawValue{Tag: 4, Bytes: []byte{0x01, 0x02}}},
				EncryptedContent:           asn1.RawValue{Class: 2, Bytes: make([]byte, block.BlockSize())},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.content.decrypt(key); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestUnpadRejectsOutOfRangePadding verifies that a padding length that is
// zero or larger than a block results in an error, not an out-of-bounds panic.
func TestUnpadRejectsOutOfRangePadding(t *testing.T) {
	for _, padlen := range []byte{0x00, 0x11, 0x20, 0xff} {
		data := bytes.Repeat([]byte{padlen}, 16)
		if _, err := unpad(data, 16); err == nil {
			t.Fatalf("expected an error for padding length %d", padlen)
		}
	}

	// Valid padding of every allowed length is still accepted.
	for padlen := 1; padlen <= 16; padlen++ {
		data := append(bytes.Repeat([]byte("a"), 16-padlen), bytes.Repeat([]byte{byte(padlen)}, padlen)...)
		out, err := unpad(data, 16)
		if err != nil {
			t.Fatalf("unexpected error for padding length %d: %v", padlen, err)
		}
		if !bytes.Equal(out, data[:16-padlen]) {
			t.Fatalf("unexpected unpadded data for padding length %d", padlen)
		}
	}
}

// TestDecryptUsingPSKKeyLength verifies that a pre-shared key of the wrong
// length is rejected without panicking.
func TestDecryptUsingPSKKeyLength(t *testing.T) {
	current := ContentEncryptionAlgorithm
	ContentEncryptionAlgorithm = EncryptionAlgorithmAES256GCM
	defer func() { ContentEncryptionAlgorithm = current }()

	encrypted, err := EncryptUsingPSK([]byte("secret"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range [][]byte{nil, {}, make([]byte, 16), make([]byte, 31), make([]byte, 33)} {
		if _, err := p7.DecryptUsingPSK(key); err == nil {
			t.Fatalf("expected an error for a %d byte pre-shared key", len(key))
		}
	}
	// The correct key still works.
	out, err := p7.DecryptUsingPSK(make([]byte, 32))
	if err != nil {
		t.Fatalf("cannot decrypt with the correct pre-shared key: %v", err)
	}
	if !bytes.Equal(out, []byte("secret")) {
		t.Fatalf("unexpected plaintext: %q", out)
	}
}

// failingDecrypter is a crypto.Decrypter that always reports a key
// decryption failure, like a hardware-backed key rejecting a malformed
// ciphertext.
type failingDecrypter struct{}

func (failingDecrypter) Public() crypto.PublicKey { return nil }

func (failingDecrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return nil, errors.New("key decryption failed")
}

// garbageDecrypter is a crypto.Decrypter that always returns a content key of
// the wrong length.
type garbageDecrypter struct{}

func (garbageDecrypter) Public() crypto.PublicKey { return nil }

func (garbageDecrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return []byte{0x01, 0x02, 0x03}, nil
}

// TestDecryptGenericDecrypterFailures verifies that a crypto.Decrypter that is
// not an *rsa.PrivateKey cannot change the observable failure behaviour.
func TestDecryptGenericDecrypterFailures(t *testing.T) {
	fixture := UnmarshalTestFixture(RSAPKCS1v15EncryptedTestFixture)
	cert := fixture.Certificate
	_, eci := mustEncryptAESCBC(t, []byte("This is a test"), make([]byte, 32))

	for name, pkey := range map[string]crypto.PrivateKey{
		"decrypter rejects the ciphertext": failingDecrypter{},
		"decrypter returns a bad key":      garbageDecrypter{},
	} {
		t.Run(name, func(t *testing.T) {
			p7 := envelopeForKeyEncryptionAlgorithm(t, cert, OIDEncryptionAlgorithmRSA, make([]byte, 256), *eci)
			out, err := p7.Decrypt(cert, pkey)
			if !errors.Is(err, ErrDecryption) {
				t.Fatalf("expected ErrDecryption, got %v", err)
			}
			if out != nil {
				t.Fatalf("expected no plaintext on failure, got %q", out)
			}
		})
	}
}

func mustEncryptAESCBC(t *testing.T, content, key []byte) ([]byte, *encryptedContentInfo) {
	t.Helper()
	current := ContentEncryptionAlgorithm
	ContentEncryptionAlgorithm = EncryptionAlgorithmAES256CBC
	defer func() { ContentEncryptionAlgorithm = current }()

	derivedKey, eci, err := encryptAESCBC(content, key)
	if err != nil {
		t.Fatalf("cannot encrypt content: %v", err)
	}
	return derivedKey, eci
}

func mustEncryptPKCS1v15(t *testing.T, pub *rsa.PublicKey, key []byte) []byte {
	t.Helper()
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	if err != nil {
		t.Fatalf("cannot encrypt key: %v", err)
	}
	return encrypted
}

// cbcCiphertextForBlock encrypts a single AES-CBC block using key and iv, so
// that decryption with the same parameters yields exactly that block.
func cbcCiphertextForBlock(t *testing.T, key, iv, block []byte) []byte {
	t.Helper()
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cannot create AES cipher: %v", err)
	}
	out := make([]byte, len(block))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(out, block)
	return out
}

// envelopeForKeyEncryptionAlgorithm builds a parsed enveloped-data structure
// with a single recipient matching cert that uses alg to encrypt the content
// key.
func envelopeForKeyEncryptionAlgorithm(t *testing.T, cert *x509.Certificate, alg asn1.ObjectIdentifier, encryptedKey []byte, content encryptedContentInfo) *PKCS7 {
	t.Helper()
	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		t.Fatalf("cannot determine issuer and serial: %v", err)
	}
	return &PKCS7{raw: envelopedData{
		Version: 0,
		RecipientInfos: []recipientInfo{{
			Version:                0,
			IssuerAndSerialNumber:  ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: alg},
			EncryptedKey:           encryptedKey,
		}},
		EncryptedContentInfo: content,
	}}
}

// encodePKCS1v15EM builds the encoded message that RSAES-PKCS1-v1_5 decryption
// expects. A block type of 0x02 with at least eight non-zero padding bytes is
// valid; any other block type is invalid.
func encodePKCS1v15EM(t *testing.T, priv *rsa.PrivateKey, blockType byte, key []byte) []byte {
	t.Helper()
	k := priv.Size()
	if k < len(key)+11 {
		t.Fatalf("key of %d bytes is too large for a %d-bit modulus", len(key), priv.N.BitLen())
	}
	em := make([]byte, k)
	em[1] = blockType
	for i := 2; i < k-len(key)-1; i++ {
		em[i] = 0xff
	}
	em[k-len(key)-1] = 0x00
	copy(em[k-len(key):], key)
	return em
}

// rsaCiphertextForEM computes the ciphertext that RSA decryption maps to em,
// using the public key. It lets tests exercise arbitrary encoded messages.
func rsaCiphertextForEM(t *testing.T, priv *rsa.PrivateKey, em []byte) []byte {
	t.Helper()
	if len(em) != priv.Size() {
		t.Fatalf("encoded message has length %d, want %d", len(em), priv.Size())
	}
	m := new(big.Int).SetBytes(em)
	if m.Cmp(priv.N) >= 0 {
		t.Fatal("encoded message is not smaller than the modulus")
	}
	c := new(big.Int).Exp(m, big.NewInt(int64(priv.PublicKey.E)), priv.N)
	out := make([]byte, priv.Size())
	copy(out[len(out)-len(c.Bytes()):], c.Bytes())
	return out
}
