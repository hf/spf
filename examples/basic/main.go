package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/hf/spf"
)

func main() {
	verifier := spf.NewVerifierWithDefaults()

	verifier.ServerIP = net.ParseIP("1.1.1.1")
	verifier.ClientIP = net.ParseIP("64.233.164.0")

	verifier.FROM = "someone@gmail.com"
	verifier.EHLO = "tx.gmail.com"
	verifier.SMTP = "rx.example.com"

	if !verifier.Check() {
		fmt.Println("You forgot to specify some mandatory field in Verifier")
		os.Exit(1)
	}

	session := spf.Session{
		Verifier: verifier,
		Domain:   "gmail.com",
	}

	result, err := session.Evaluate(context.TODO())

	fmt.Printf("Result: %q\n", result)
	fmt.Printf("Error: %T %v\n", err, err)
	fmt.Printf("Mechanism: %q\n", session.Mechanisms)
	fmt.Printf("Explanation: %q\n", session.Explanation)
	fmt.Printf("DNS Queries: %v\n", session.DNSQueries)
}
