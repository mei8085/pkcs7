//go:build go1.20
// +build go1.20

package pkcs7

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// oaepDecrypterOptions converts a fully resolved RSAES-OAEP parameter
// contract into the options used for RSA decryption. The digest, MGF1 digest
// and label all come from the same rsaOAEPParameters value that was parsed
// from (or written to) the key encryption algorithm identifier, so the
// operation can only use what the envelope declares.
func oaepDecrypterOptions(params rsaOAEPParameters) (crypto.DecrypterOpts, error) {
	if !params.Hash.Available() {
		return nil, fmt.Errorf("%w: OAEP digest algorithm %v is not available", ErrInvalidOAEPParameters, params.Hash)
	}
	if !params.MGFHash.Available() {
		return nil, fmt.Errorf("%w: OAEP MGF1 digest algorithm %v is not available", ErrInvalidOAEPParameters, params.MGFHash)
	}
	return &rsa.OAEPOptions{
		Hash:    params.Hash,
		MGFHash: params.MGFHash,
		Label:   params.Label,
	}, nil
}
