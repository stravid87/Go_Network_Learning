package main

import (
	"context"
	"log"
	"net"

	"proto"

	"google.golang.org/grpc"
)

type Server struct {
	proto.UnimplementedChatServiceServer
}

func (s *Server) SendLorem(ctx context.Context, req *proto.Message) (*proto.Message, error) {
    return &proto.Message{Body: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":9090")
	if err != nil {
		log.Fatalf("Failed to listen on port 9090: %v", err)
	}

	grpcServer := grpc.NewServer()

	proto.RegisterChatServiceServer(grpcServer, &Server{})

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC server over port 9090: %v", err)
	}
	
}
