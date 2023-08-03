package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"syscall/js"
)

// func SayHello(this js.Value, args []js.Value) interface{} {
// 	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
// 		resolve := args[0]
// 		//reject := args[1]
// 		go func() {
// 			//reject.Invoke(js.ValueOf(""))
// 			resolve.Invoke(js.ValueOf("Hello!"))
// 		}()
// 		return nil
// 	}
// 	promiseConstructor := js.Global().Get("Promise")
// 	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
// 	return promise
// }

// func PingBackend(this js.Value, args []js.Value) interface{} {
// 	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
// 		resolve := args[0]
// 		reject := args[1]
// 		go func() {
// 			resp, err := http.Get("http://localhost:8080/ping")
// 			if err != nil {
// 				reject.Invoke("Failure to ping backend. Error: ", js.ValueOf(err.Error()))
// 				return
// 			}
// 			if resp == nil || resp.Body == nil || resp.StatusCode != http.StatusOK {
// 				reject.Invoke(js.ValueOf(fmt.Errorf("500 error from server? ", err.Error())))
// 				return
// 			}

// 			response_BS, err := ioutil.ReadAll(resp.Body)
// 			if err != nil {
// 				reject.Invoke(js.ValueOf(fmt.Errorf("Error reading response body: ", err.Error())))
// 			}
// 			fmt.Println("I should be a successful ping...")
// 			resolve.Invoke(js.ValueOf(string(response_BS)))
// 		}()
// 		return nil
// 	}
// 	promiseConstructor := js.Global().Get("Promise")
// 	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
// 	return promise
// }

func HashString(this js.Value, args []js.Value) interface{} {
	jsString := args[0].String()
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func(jsString string) {
			hash := sha256.New()
			if _, err := hash.Write([]byte(jsString)); err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("HashMessage of WASM module failed with error %s", err.Error())))
			}
			str_hex := hex.EncodeToString(hash.Sum(nil))
			resolve.Invoke(js.ValueOf(str_hex))
		}(jsString)
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func SignString(this js.Value, args []js.Value) interface{} {
	arg0BS := []byte(args[0].String())
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func(input []byte) {
			hash, err := HashByteSlice(input)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error hashing: \"%s\"", err.Error())))
			}
			signatureASN1, err := SignByteSliceASN1(KeyPairS_c.privSK_ptr, hash)
			resolve.Invoke(js.ValueOf(StringToBase64(signatureASN1)))
		}(arg0BS)
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}

func SendPost(this js.Value, args []js.Value) interface{} {
	comingData := args[0].String()
	resolve_reject_internals := func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func() {
			var url = "http://localhost:9091/post-ur-hash"
			simplePost := SimplePost{
				Id:     0,
				Title:  comingData,
				Body:   "This is body",
				UserId: 99,
			}
			simplePost_bs, err := json.Marshal(simplePost)
			if err != nil {
				fmt.Errorf("Error on POST to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on Post"))
			}

			resp, err := http.Post(url, "Content-Type:application/json", bytes.NewReader(simplePost_bs))
			if err != nil {
				fmt.Errorf("Error on POST to %s: %s", url, err.Error())
				reject.Invoke(js.ValueOf("Failure on Post"))
			}

			defer resp.Body.Close()

			response_BS, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Errorf("Error reading response body: ", err.Error())))
			}

			resolve.Invoke(js.ValueOf(fmt.Sprintf("I got << %s >> in response to sendPost.", string(response_BS))))
		}()
		return nil
	}
	promiseConstructor := js.Global().Get("Promise")
	promise := promiseConstructor.New(js.FuncOf(resolve_reject_internals))
	return promise
}