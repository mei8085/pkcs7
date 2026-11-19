package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ErrUnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, DES, DES-EDE3, AES-256-CBC and AES-128-GCM supported")

// ErrUnsupportedAsymmetricEncryptionAlgorithm is returned when attempting to use an unknown asymmetric encryption algorithm
var ErrUnsupportedAsymmetricEncryptionAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA PKCS#1 v1.5 and RSA OAEP are supported")

// ErrUnsupportedKeyType is returned when attempting to encrypting keys using a key that's not an RSA key
var ErrUnsupportedKeyType = errors.New("pkcs7: only RSA keys are supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	switch pkey := pkey.(type) {
	case crypto.Decrypter:
		var opts crypto.DecrypterOpts
		switch algorithm := recipient.KeyEncryptionAlgorithm.Algorithm; {
		case algorithm.Equal(OIDEncryptionAlgorithmRSAESOAEP):
			// Resolve and validate the complete OAEP contract (digest, MGF1
			// digest and label) before touching the encrypted key. Any
			// missing, conflicting or unrecognized parameter is reported
			// here, before any RSA operation takes place.
			params, err := getOAEPParametersForKeyEncryptionAlgorithm(recipient.KeyEncryptionAlgorithm)
			if err != nil {
				return nil, err
			}
			opts, err = oaepDecrypterOptions(params)
			if err != nil {
				return nil, err
			}
		case algorithm.Equal(OIDEncryptionAlgorithmRSA):
			opts = &rsa.PKCS1v15DecryptOptions{}
		default:
			return nil, ErrUnsupportedAsymmetricEncryptionAlgorithm
		}
		contentKey, err := pkey.Decrypt(rand.Reader, recipient.EncryptedKey, opts)
		if err != nil {
			// A custom crypto.Decrypter is allowed to return a buffer even
			// on failure; never leave key material behind.
			wipeBytes(contentKey)
			return nil, err
		}
		// The content encryption key is only needed for the symmetric
		// decryption below. Wipe it on every return path, including error
		// paths, so it does not linger in memory after this call and cannot
		// leak into error reporting.
		defer wipeBytes(contentKey)
		return data.EncryptedContentInfo.decrypt(contentKey)
	}
	return nil, ErrUnsupportedAlgorithm
}

// wipeBytes overwrites b in place. It is used to discard the content
// encryption key once it has served its purpose.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// getOAEPParametersForKeyEncryptionAlgorithm resolves the RSAES-OAEP
// parameters declared by a key encryption algorithm identifier into the exact
// contract to use for the RSA operation. It never falls back to a guess: an
// absent, malformed, duplicated, conflicting or unrecognized parameter is
// reported as ErrInvalidOAEPParameters.
func getOAEPParametersForKeyEncryptionAlgorithm(keyEncryptionAlgorithm pkix.AlgorithmIdentifier) (rsaOAEPParameters, error) {
	if !keyEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSAESOAEP) {
		return rsaOAEPParameters{}, fmt.Errorf("%w: algorithm %v is not RSAES-OAEP",
			ErrInvalidOAEPParameters, keyEncryptionAlgorithm.Algorithm)
	}
	return parseRSAOAEPParameters(keyEncryptionAlgorithm.Parameters)
}

// getHashFuncForKeyEncryptionAlgorithm returns the OAEP digest algorithm
// declared by a key encryption algorithm identifier.
//
// It is the digest-only view of getOAEPParametersForKeyEncryptionAlgorithm and
// still validates the whole parameter set, so it does not accept parameters
// that the full contract would reject.
func getHashFuncForKeyEncryptionAlgorithm(keyEncryptionAlgorithm pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	params, err := getOAEPParametersForKeyEncryptionAlgorithm(keyEncryptionAlgorithm)
	if err != nil {
		return crypto.Hash(0), err
	}
	return params.Hash, nil
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret
func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, error) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return data.EncryptedContentInfo.decrypt(key)
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	if !alg.Equal(OIDEncryptionAlgorithmDESCBC) &&
		!alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES256CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES128CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES128GCM) &&
		!alg.Equal(OIDEncryptionAlgorithmAES256GCM) {
		return nil, ErrUnsupportedAlgorithm
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
	var err error

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

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("pkcs7: invalid padding")
		}
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
