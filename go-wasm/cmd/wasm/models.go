package main

import "crypto/ecdh"

type KeyPairSigning struct {
	privSK_bs []byte
	pubSK_bs  []byte
}

type KeyPairDH struct {
	privDHK_ptr *ecdh.PrivateKey
	pubDHK_ptr  *ecdh.PublicKey
}
