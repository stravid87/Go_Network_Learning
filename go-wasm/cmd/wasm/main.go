package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	fmt.Println("Hello from WASM")
	wasmBlockingChan := make(chan struct{})
	js.Global().Set("sayHello", js.FuncOf(SayHello))
	js.Global().Set("hashMessage", js.FuncOf(HashString))

	fmt.Println("Wasm fully loaded")
	<-wasmBlockingChan
}
