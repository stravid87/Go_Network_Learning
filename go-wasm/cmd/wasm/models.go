package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
)

type KeyPairSigning struct {
	privSK_ptr *ecdsa.PrivateKey
	pubSK_val  crypto.PublicKey
}

type KeyPairDH struct {
	privDHK_ptr *ecdh.PrivateKey
	pubDHK_ptr  *ecdh.PublicKey
}
