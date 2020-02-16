// Package kx25519 implements libsodium-compatible key exchange on Curve25519 with blake2b-512 hashing
package kx25519

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

// KeySize is the size in bytes of all keys in this package.
const KeySize = 32

// Genkey generates a private key using randomness from rnd or crypt/rand.Reader if nil
func Genkey(rnd io.Reader) (sk []byte, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	sk = make([]byte, KeySize)
	if _, err = io.ReadFull(rnd, sk); err != nil {
		return nil, err
	}
	return sk, nil
}

// Pubkey computes the public key corresponding to the secret key
func Pubkey(sk []byte) (pk []byte, err error) { return curve25519.X25519(sk, curve25519.Basepoint) }

// KeyPair generates a random pair of public and private keys.
func KeyPair(rnd io.Reader) (pk, sk []byte, err error) {
	sk, err = Genkey(rnd)
	if err != nil {
		return nil, nil, err
	}
	pk, err = Pubkey(sk)
	return
}

// ClientSessionKeys computes client receive (rx) and transmit (tx) keys given the client's public key (pk), private key (sk), and server's public key (ppk).
func ClientSessionKeys(pk, sk, ppk []byte) (rx, tx []byte, err error) {
	shared, err := curve25519.X25519(sk, ppk)
	if err != nil {
		return nil, nil, err
	}
	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, nil, err
	}
	if _, err = h.Write(shared); err != nil {
		return nil, nil, err
	}
	if _, err = h.Write(pk); err != nil {
		return nil, nil, err
	}
	if _, err = h.Write(ppk); err != nil {
		return nil, nil, err
	}
	ks := h.Sum(nil)
	return ks[:KeySize], ks[KeySize:], nil
}

// ServerSessionKeys computes server receive (rx) and transmit (tx) keys given the server's public key (pk), private key (sk), and client's public key (ppk).
func ServerSessionKeys(pk, sk, ppk []byte) (rx, tx []byte, err error) {
	shared, err := curve25519.X25519(sk, ppk)
	if err != nil {
		return nil, nil, err
	}
	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, nil, err
	}
	if _, err = h.Write(shared); err != nil {
		return nil, nil, err
	}
	if _, err = h.Write(ppk); err != nil {
		return nil, nil, err
	}
	if _, err = h.Write(pk); err != nil {
		return nil, nil, err
	}
	ks := h.Sum(nil)
	return ks[KeySize:], ks[:KeySize], nil
}
