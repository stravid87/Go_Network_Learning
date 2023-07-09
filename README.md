# Project Title: Small Networking in Golang

This project is an experiment with Wasm, Proto Buffer, Symmetric encryption in Golang. The project is designed with several servers, where one data is sent from the first server to the second server using gRPC. The second server then sends that data to the frontend server using HTTP. The data is then displayed on the frontend using JavaScript, specifically Vue.js.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Ensure you have the following installed on your system:

- Go
- Protoc Compiler
- Vue.js

### Installation

- Clone this repository to your local machine to start using it. 

```bash
git clone https://github.com/globe-and-citizen/Go_Network_Learning.git
```

- Change directory into the project folder. 

```bash
cd Go_Networking_Learning
```

- Install all the necessary dependencies. 

## Usage 

This project has several servers and data is sent from the first server to the second server using gRPC. The second server then sends that data to the frontend server using HTTP. 

The data is displayed on the frontend using Vue.js. 

## Proto Buffer

This project uses Protocol Buffers (Proto Buffer) to structure the protocol buffer data. Proto Buffer is a language-neutral, platform-neutral, extensible mechanism developed by Google for serializing structured data[Source 0](https://developers.google.com/protocol-buffers/docs/proto3). It is useful in developing programs to communicate with each other over a network or for storing data.

## WASM

WebAssembly (abbreviated Wasm) is a binary instruction format for a stack-based virtual machine. Wasm is designed as a portable target for the compilation of high-level languages like C, C++, and Rust, enabling deployment on the web for client and server applications[Source 3](https://github.com/grpc/grpc-go/issues/2294).

## Symmetric Encryption

This project uses symmetric encryption for encryption and decryption of data. In symmetric encryption, a single key is used for encryption and decryption.

## Built With

- Golang - The backend language used
- Vue.js - The frontend framework used
- gRPC - A high-performance, open-source universal RPC framework.
- Protocol Buffers (protobuf) - Google's language-neutral, platform-neutral, extensible mechanism for serializing structured data.

## Contributors

Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests to us.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details

## Acknowledgments

- Hat tip to anyone whose code was used
- Inspiration
- etc.
