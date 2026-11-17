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

// ErrMalformedEncryptedContent is returned when the ASN.1 structure of the
// encrypted content itself is malformed, e.g. a truncated constructed
// OCTET STRING. No plaintext is produced in this case.
var ErrMalformedEncryptedContent = errors.New("pkcs7: malformed encrypted content")

// ErrInvalidCiphertextLength is returned when the ciphertext is empty or its
// length is not a multiple of the cipher block size.
var ErrInvalidCiphertextLength = errors.New("pkcs7: invalid ciphertext length")

// ErrInvalidPadding is returned when the PKCS#7 padding of the decrypted
// content is invalid: a padding length of zero, a padding length larger
// than the block size, or padding bytes that are not all identical.
var ErrInvalidPadding = errors.New("pkcs7: invalid padding")

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
			hashFunc, err := getHashFuncForKeyEncryptionAlgorithm(recipient.KeyEncryptionAlgorithm)
			if err != nil {
				return nil, err
			}
			opts = &rsa.OAEPOptions{Hash: hashFunc}
		case algorithm.Equal(OIDEncryptionAlgorithmRSA):
			opts = &rsa.PKCS1v15DecryptOptions{}
		default:
			return nil, ErrUnsupportedAsymmetricEncryptionAlgorithm
		}
		contentKey, err := pkey.Decrypt(rand.Reader, recipient.EncryptedKey, opts)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	}
	return nil, ErrUnsupportedAlgorithm
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
		// Complex case to concat all of the children OCTET STRINGs. Any
		// parsing failure aborts the whole decryption: no partial
		// ciphertext (and hence no partial plaintext) may be produced.
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for len(cypherbytes) > 0 {
			var part []byte
			rest, err := asn1.Unmarshal(cypherbytes, &part)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedEncryptedContent, err)
			}
			if len(rest) >= len(cypherbytes) {
				// defensive: parsing must make progress
				return nil, ErrMalformedEncryptedContent
			}
			buf.Write(part)
			cypherbytes = rest
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
	// The ciphertext must be a non-empty multiple of the block size;
	// checking before decrypting keeps cipher.CryptBlocks from panicking
	// and guarantees no partial plaintext is ever produced.
	if len(cyphertext) == 0 || len(cyphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: ciphertext length %d is not a multiple of block size %d",
			ErrInvalidCiphertextLength, len(cyphertext), block.BlockSize())
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
		return nil, fmt.Errorf("%w: %d", ErrInvalidCiphertextLength, len(data))
	}

	// the last byte is the length of the padding
	padlen := int(data[len(data)-1])

	// the padding must consist of at least one byte and at most a full
	// block; anything else is invalid and must not be used to slice data
	if padlen < 1 || padlen > blocklen || padlen > len(data) {
		return nil, fmt.Errorf("%w: invalid padding length %d", ErrInvalidPadding, padlen)
	}

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, ErrInvalidPadding
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
