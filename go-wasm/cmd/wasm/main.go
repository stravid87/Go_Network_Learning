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
	fmt.Println("Hello from WASM")
	wasmBlockingChan := make(chan struct{})
	js.Global().Set("sayHello", js.FuncOf(SayHello))
	js.Global().Set("pingBackend", js.FuncOf(PingBackend))
	js.Global().Set("hashMessage", js.FuncOf(HashString))
	js.Global().Set("signString", js.FuncOf(SignString)) //byteSlice ASN1 encoded
	fmt.Println("Wasm fully loaded")
	<-wasmBlockingChan
}
