package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// Crypto hash constants for RSA verification.
var (
	cryptoSHA256 = crypto.SHA256
	cryptoSHA384 = crypto.SHA384
	cryptoSHA512 = crypto.SHA512
)

// newSHA256 returns a new SHA256 hash.
func newSHA256() hash.Hash {
	return sha256.New()
}

// newSHA384 returns a new SHA384 hash.
func newSHA384() hash.Hash {
	return sha512.New384()
}

// newSHA512 returns a new SHA512 hash.
func newSHA512() hash.Hash {
	return sha512.New()
}

// rsaVerifyPKCS1v15 verifies an RSA PKCS#1 v1.5 signature.
func rsaVerifyPKCS1v15(pub *rsa.PublicKey, hashAlg crypto.Hash, hashed, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, hashAlg, hashed, sig)
}

// rsaVerifyPSS verifies an RSA-PSS signature.
// Uses PSSSaltLengthEqualsHash for maximum compatibility with JWT libraries.
func rsaVerifyPSS(pub *rsa.PublicKey, hashAlg crypto.Hash, hashed, sig []byte) error {
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hashAlg,
	}
	return rsa.VerifyPSS(pub, hashAlg, hashed, sig, opts)
}
