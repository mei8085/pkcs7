package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
)

// ErrUnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, DES, DES-EDE3, AES-256-CBC and AES-128-GCM supported")

// ErrUnsupportedAsymmetricEncryptionAlgorithm is returned when attempting to use an unknown asymmetric encryption algorithm
var ErrUnsupportedAsymmetricEncryptionAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA PKCS#1 v1.5 and RSA OAEP are supported")

// ErrUnsupportedKeyType is returned when attempting to encrypting keys using a key that's not an RSA key
var ErrUnsupportedKeyType = errors.New("pkcs7: only RSA keys are supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

// ErrDecryption is returned when the encrypted content key or the encrypted
// content itself cannot be decrypted. The cause is deliberately not reported
// in detail: invalid padding, an unusable content key and a failure to decrypt
// the content all produce this exact same error, so that they cannot be told
// apart (see RFC 3218, Preventing the Million Message Attack on Cryptographic
// Message Syntax).
var ErrDecryption = errors.New("pkcs7: decryption failed")

// Decrypt decrypts encrypted content info for recipient cert and private key.
//
// RSAES-PKCS1-v1_5 encrypted content keys are decrypted using implicit
// rejection: a random content key of the size required by the content
// encryption algorithm is used whenever the encrypted key is malformed or
// cannot be recovered. The content decryption is always attempted, so invalid
// padding, a content key of the wrong length and a failure to decrypt the
// content are indistinguishable through the returned error or through the
// sequence of operations performed.
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	if cert == nil {
		return nil, errors.New("pkcs7: no certificate provided")
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	decrypter, ok := pkey.(crypto.Decrypter)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	// The content encryption algorithm is part of the message and does not
	// depend on the encrypted key, so failing here does not leak any
	// information about the encrypted key's padding.
	keyLen, err := contentEncryptionKeyLen(data.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}

	// Generate a random content key up front, regardless of the outcome of
	// the key decryption below, so the work performed does not depend on the
	// validity of the encrypted key.
	fallbackKey, err := randomContentKey(keyLen)
	if err != nil {
		return nil, err
	}

	var contentKey []byte
	keyOK := true
	switch algorithm := recipient.KeyEncryptionAlgorithm.Algorithm; {
	case algorithm.Equal(OIDEncryptionAlgorithmRSAESOAEP):
		hashFunc, err := getHashFuncForKeyEncryptionAlgorithm(recipient.KeyEncryptionAlgorithm)
		if err != nil {
			return nil, err
		}
		contentKey, err = decrypter.Decrypt(rand.Reader, recipient.EncryptedKey, &rsa.OAEPOptions{Hash: hashFunc})
		if err != nil || len(contentKey) != keyLen {
			keyOK = false
		}
	case algorithm.Equal(OIDEncryptionAlgorithmRSA):
		contentKey, keyOK = decryptPKCS1v15ContentKey(decrypter, recipient.EncryptedKey, keyLen)
	default:
		return nil, ErrUnsupportedAsymmetricEncryptionAlgorithm
	}
	if !keyOK {
		// Continue with the random key so that the content decryption runs
		// unconditionally, whether the content key could be recovered or not.
		contentKey = fallbackKey
	}

	// The content decryption is attempted even when the content key could not
	// be recovered, so that the same work is performed in every case.
	plaintext, err := data.EncryptedContentInfo.decrypt(contentKey)
	if err != nil || !keyOK {
		// Do not expose why the content could not be decrypted: invalid
		// padding, a content key of an unexpected size and corrupt content
		// must all fail in the same way.
		return nil, ErrDecryption
	}
	return plaintext, nil
}

// decryptPKCS1v15ContentKey decrypts a content encryption key using RSAES-
// PKCS1-v1_5. If the encrypted key is not validly padded or does not contain a
// key of exactly keyLen bytes, keyOK is false; the caller must then continue
// with the content decryption using a random key of keyLen bytes, but report a
// uniform failure, so that padding validity is not observable (see RFC 3218,
// Preventing the Million Message Attack on Cryptographic Message Syntax).
func decryptPKCS1v15ContentKey(decrypter crypto.Decrypter, encryptedKey []byte, keyLen int) (contentKey []byte, keyOK bool) {
	// The padding is verified by crypto/rsa in constant time. A malformed
	// ciphertext, invalid padding and a recovered key of the wrong size are
	// all collapsed into keyOK being false, without reporting which happened.
	contentKey, err := decrypter.Decrypt(rand.Reader, encryptedKey, &rsa.PKCS1v15DecryptOptions{})
	if err != nil || len(contentKey) != keyLen {
		return nil, false
	}
	return contentKey, true
}

// randomContentKey returns a random content encryption key of keyLen bytes.
func randomContentKey(keyLen int) ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// RFC 4055, 4.1
// The current ASN.1 parser does not support non-integer defaults so the 'default:' tags here do nothing.
type rsaOAEPAlgorithmParameters struct {
	HashFunc    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0,default:sha1Identifier"`
	MaskGenFunc pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1,default:mgf1SHA1Identifier"`
	PSourceFunc pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:2,default:pSpecifiedEmptyIdentifier"`
}

func getHashFuncForKeyEncryptionAlgorithm(keyEncryptionAlgorithm pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	invalidHashFunc := crypto.Hash(0)
	params := &rsaOAEPAlgorithmParameters{
		HashFunc: pkix.AlgorithmIdentifier{Algorithm: OIDDigestAlgorithmSHA1}, // set default hash algorithm to SHA1
	}
	var rest []byte
	rest, err := asn1.Unmarshal(keyEncryptionAlgorithm.Parameters.FullBytes, params)
	if err != nil {
		return invalidHashFunc, fmt.Errorf("pkcs7: failed unmarshaling key encryption algorithm parameters: %v", err)
	}
	if len(rest) != 0 {
		return invalidHashFunc, errors.New("pkcs7: trailing data after RSA OAEP parameters")
	}

	switch {
	case params.HashFunc.Algorithm.Equal(OIDDigestAlgorithmSHA1):
		return crypto.SHA1, nil
	case params.HashFunc.Algorithm.Equal(OIDDigestAlgorithmSHA224):
		return crypto.SHA224, nil
	case params.HashFunc.Algorithm.Equal(OIDDigestAlgorithmSHA256):
		return crypto.SHA256, nil
	case params.HashFunc.Algorithm.Equal(OIDDigestAlgorithmSHA384):
		return crypto.SHA384, nil
	case params.HashFunc.Algorithm.Equal(OIDDigestAlgorithmSHA512):
		return crypto.SHA512, nil
	default:
		return invalidHashFunc, errors.New("pkcs7: unsupported hash function for RSA OAEP")
	}
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret. The key must have the length required by the content
// encryption algorithm of the message (for example 32 bytes for AES-256-CBC).
func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, error) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return data.EncryptedContentInfo.decrypt(key)
}

// contentEncryptionKeyLen returns the length in bytes of the content
// encryption key required by alg. It returns ErrUnsupportedAlgorithm for
// algorithms that are not supported.
func contentEncryptionKeyLen(alg asn1.ObjectIdentifier) (int, error) {
	switch {
	case alg.Equal(OIDEncryptionAlgorithmDESCBC):
		return 8, nil
	case alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC):
		return 24, nil
	case alg.Equal(OIDEncryptionAlgorithmAES128CBC), alg.Equal(OIDEncryptionAlgorithmAES128GCM):
		return 16, nil
	case alg.Equal(OIDEncryptionAlgorithmAES256CBC), alg.Equal(OIDEncryptionAlgorithmAES256GCM):
		return 32, nil
	default:
		return 0, ErrUnsupportedAlgorithm
	}
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	keyLen, err := contentEncryptionKeyLen(alg)
	if err != nil {
		return nil, err
	}
	// Enforce the key length required by the content encryption algorithm
	// before the key is used, so that all content encryption algorithms
	// validate their keys in the same way.
	if len(key) != keyLen {
		return nil, errors.New("pkcs7: invalid content encryption key length")
	}

	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	var cyphertext []byte
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		cyphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		cyphertext = eci.EncryptedContent.Bytes
	}

	var block cipher.Block

	switch {
	case alg.Equal(OIDEncryptionAlgorithmDESCBC):
		block, err = des.NewCipher(key)
	case alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
	case alg.Equal(OIDEncryptionAlgorithmAES256CBC), alg.Equal(OIDEncryptionAlgorithmAES256GCM):
		fallthrough
	case alg.Equal(OIDEncryptionAlgorithmAES128GCM), alg.Equal(OIDEncryptionAlgorithmAES128CBC):
		block, err = aes.NewCipher(key)
	}

	if err != nil {
		return nil, err
	}

	if alg.Equal(OIDEncryptionAlgorithmAES128GCM) || alg.Equal(OIDEncryptionAlgorithmAES256GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}

		plaintext, err := gcm.Open(nil, params.Nonce, cyphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	// CryptBlocks panics when the input is not a whole number of blocks;
	// reject such input instead of crashing.
	if len(cyphertext) == 0 || len(cyphertext)%block.BlockSize() != 0 {
		return nil, errors.New("pkcs7: encrypted content is malformed")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("pkcs7: invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("pkcs7: invalid data len %d", len(data))
	}

	// The last byte is the length of the padding. Because len(data) is a
	// multiple of blocklen, data is at least one full block long.
	padlen := int(data[len(data)-1])

	// Check the padding without branching on whether it is valid: every byte
	// of a full block is inspected and out-of-range padding lengths are
	// rejected defensively instead of indexing out of bounds.
	valid := subtle.ConstantTimeLessOrEq(1, padlen) &
		subtle.ConstantTimeLessOrEq(padlen, blocklen)
	for i := 1; i <= blocklen; i++ {
		inPad := subtle.ConstantTimeLessOrEq(i, padlen)
		matches := subtle.ConstantTimeByteEq(data[len(data)-i], byte(padlen))
		valid &= (inPad ^ 1) | matches
	}
	if valid != 1 {
		return nil, errors.New("pkcs7: invalid padding")
	}

	return data[:len(data)-padlen], nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *x509.Certificate) recipientInfo {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp
		}
	}
	return recipientInfo{}
}
