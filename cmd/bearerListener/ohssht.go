package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	_ "github.com/goschtalt/yaml-decoder"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func startRevSSHServer() {
	// Connect to the ssh-agent
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Fatalf("Failed to connect to ssh-agent: %v", err)
	}
	defer sshAgent.Close()

	agentClient := agent.NewClient(sshAgent)

	// List the keys in the ssh-agent
	keys, err := agentClient.List()
	if err != nil {
		log.Fatalf("Failed to list keys from ssh-agent: %v", err)
	}

	// Use the first key from the ssh-agent
	if len(keys) == 0 {
		log.Fatalf("No keys found in ssh-agent")
	}

	// Get the private key from the ssh-agent
	signers, err := agentClient.Signers()
	if err != nil {
		log.Fatalf("Failed to get signers from ssh-agent: %v", err)
	}

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
		//ssh.HostbasedAuthentication: true,
		//User: "rocky",
		/*
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(privateKey),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		*/
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			if err != nil {
				log.Printf("Failed authentication for %s from %s: %v", conn.User(), conn.RemoteAddr(), err)
			} else {
				log.Printf("Successful authentication for %s from %s", conn.User(), conn.RemoteAddr())
			}
		},
	}

	// Add the host key to the server configuration
	for _, signer := range signers {
		sshConfig.AddHostKey(signer)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		log.Fatalf("Failed to listen on 8080: %v", err)
	}
	log.Println("Listening on 0.0.0.0:8080...")

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept incoming connection: %v", err)
		}

		go handleConnection(nConn, sshConfig)
	}
}

func handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	defer nConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			return
		}
		defer channel.Close()

		// Push an exec request to the client
		go func() {
			cmd := "cat /version.txt"
			ok, err := channel.SendRequest("exec", true, ssh.Marshal(&struct{ Command string }{cmd}))
			if err != nil {
				log.Printf("Failed to send exec request: %v", err)
				return
			}
			if !ok {
				log.Printf("Exec request was rejected by the client")
				return
			}

			// Read the output from the command
			output, err := io.ReadAll(channel)
			if err != nil && errors.Is(err, io.EOF) {
				log.Printf("Failed to read output: %v", err)
				return
			}
			fmt.Printf("Command output: %s\n", string(output))

			// Schedule the channel to close after 5 seconds
			time.AfterFunc(5*time.Second, func() {
				log.Println("Closing channel after 5 seconds")

				// Send the exit status back to the client
				channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})

				// Close the channel
				channel.Close()
			})
		}()

		// Handle incoming requests on the channel
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "exec":
					req.Reply(false, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)
	}
}
