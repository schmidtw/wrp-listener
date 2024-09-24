package main

import (
	"fmt"
	"log"
	"net"
	"os"

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
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return fmt.Sprintf("Welcome to the custom SSH server.\n")
		},
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

	sshConn /*chans*/, _, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	// Extract the client's IP address
	clientAddr := sshConn.RemoteAddr().String()
	fmt.Printf("WTS: remote client address: %s", clientAddr)
	localAddr := sshConn.RemoteAddr().String()
	fmt.Printf("WTS: local client address: %s", localAddr)

	go ssh.DiscardRequests(reqs)

	fmt.Printf("WTS: Nearly there\n")

	fmt.Println("WTS About to dial")
	// Establish an SSH connection back to the client
	clientConfig := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agent.NewClient(nConn).Signers),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	fmt.Println("Dialing")
	client, err := ssh.Dial("tcp", "127.0.0.1:3002", clientConfig)
	if err != nil {
		log.Printf("Failed to dial client: %v", err)
		return
	}
	defer client.Close()

	fmt.Println("New Session")
	// Create a new session
	session, err := client.NewSession()
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		return
	}
	defer session.Close()

	fmt.Println("cat file")
	// Capture the output of the command
	output, err := session.CombinedOutput("/usr/bin/cat /version.txt")
	if err != nil {
		log.Printf("Failed to run command: %v", err)
		return
	}

	fmt.Println("Write something")
	fmt.Println(output)
	/*
		// Write the output to the channel
		_, err = channel.Write(output)
		if err != nil {
			log.Printf("Failed to write output to channel: %v", err)
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
	*/
	/*
		for newChannel := range chans {
			fmt.Println("WTS: Sanity Check")
			if newChannel.ChannelType() != "session" {
				fmt.Println("WTS: Rejection")
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
				fmt.Println("WTS About to dial")
				// Establish an SSH connection back to the client
				clientConfig := &ssh.ClientConfig{
					User: "root",
					Auth: []ssh.AuthMethod{
						ssh.PublicKeysCallback(agent.NewClient(nConn).Signers),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				}

				fmt.Println("Dialing")
				client, err := ssh.Dial("tcp", "127.0.0.1:3002", clientConfig)
				if err != nil {
					log.Printf("Failed to dial client: %v", err)
					return
				}
				defer client.Close()

				fmt.Println("New Session")
				// Create a new session
				session, err := client.NewSession()
				if err != nil {
					log.Printf("Failed to create session: %v", err)
					return
				}
				defer session.Close()

				fmt.Println("cat file")
				// Capture the output of the command
				output, err := session.CombinedOutput("/usr/bin/cat /version.txt")
				if err != nil {
					log.Printf("Failed to run command: %v", err)
					return
				}

				fmt.Println("Write something")
				// Write the output to the channel
				_, err = channel.Write(output)
				if err != nil {
					log.Printf("Failed to write output to channel: %v", err)
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
				fmt.Println("WTS incoming requests")

				for req := range in {
					req.Reply(false, nil)
				}
			}(requests)
		}
	*/
}
