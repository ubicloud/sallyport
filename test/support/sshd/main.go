// This is a fixture for the tests: an SSH server that takes the password
// "sallyport" from anyone, and answers a command by writing it back.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	// Net::SSH takes a key of this kind without a gem beyond itself.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == "sallyport" {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		},
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(conn, config)
	}
}

func serve(tcp net.Conn, config *ssh.ServerConfig) {
	defer tcp.Close()
	conn, channels, requests, err := ssh.NewServerConn(tcp, config)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(requests)
	for offered := range channels {
		if offered.ChannelType() != "session" {
			offered.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		channel, requests, err := offered.Accept()
		if err != nil {
			return
		}
		go func() {
			defer channel.Close()
			for request := range requests {
				if request.Type != "exec" {
					request.Reply(false, nil)
					continue
				}
				var exec struct{ Command string }
				ssh.Unmarshal(request.Payload, &exec)
				request.Reply(true, nil)
				fmt.Fprintf(channel, "ran: %s\n", exec.Command)
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}()
	}
}
