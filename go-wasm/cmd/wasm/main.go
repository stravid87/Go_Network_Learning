package main

import (
	"crypto/ecdh"
	"fmt"
	"syscall/js"
)

var KeyPairS_c KeyPairSigning

var KeyPairDH_c KeyPairDH

func init() {
	GenerateDHKeyPair(ecdh.P256())
	GenerateSigningKeyPair()
}

func main() {
	wasmBlockingChan := make(chan struct{})
	js.Global().Set("sendPost", js.FuncOf(SendPost))
	js.Global().Set("signString", js.FuncOf(SignString)) //byteSlice ASN1 encoded
	<-wasmBlockingChan
}
