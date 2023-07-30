server1: networking/servers/first_server.go
	go run $<

server2: networking/servers/second_server.go
	go run $<

frontend: go-wasm/cmd/front_server.go
	go run $<

update_wasm:
	GOOS=js GOARCH=wasm go build --o go-wasm/assets/main.wasm go-wasm/cmd/wasm/*