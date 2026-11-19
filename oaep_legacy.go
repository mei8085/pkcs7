//go:build !go1.20
// +build !go1.20

package pkcs7

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// oaepDecrypterOptions converts a fully resolved RSAES-OAEP parameter
// contract into the options used for RSA decryption.
//
// Before Go 1.20 crypto/rsa cannot select an MGF1 digest independently of the
// OAEP digest. Rather than silently performing the operation with the OAEP
// digest as the MGF1 digest, which would be exactly the declaration/operation
// mismatch this package must not produce, such parameters are rejected with a
// clear error. Envelopes using the all-default parameters (SHA-1 for both the
// digest and MGF1) and envelopes whose declared MGF1 digest equals the OAEP
// digest are still decrypted normally, including a non-empty label.
func oaepDecrypterOptions(params rsaOAEPParameters) (crypto.DecrypterOpts, error) {
	if params.MGFHash != params.Hash {
		return nil, fmt.Errorf("%w: OAEP digest %v with a distinct MGF1 digest %v requires Go 1.20 or newer",
			ErrInvalidOAEPParameters, params.Hash, params.MGFHash)
	}
	if !params.Hash.Available() {
		return nil, fmt.Errorf("%w: OAEP digest algorithm %v is not available", ErrInvalidOAEPParameters, params.Hash)
	}
	return &rsa.OAEPOptions{Hash: params.Hash, Label: params.Label}, nil
}
