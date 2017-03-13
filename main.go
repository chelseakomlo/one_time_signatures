package main

import (
	"fmt"
	"os"

	"github.com/chelseakomlo/one_time_signatures/lamport"
)

func main() {
	if len(os.Args) > 1 {
		message := os.Args[1]
		kp := lamport.GenLamportKeyPair()
		l := lamport.Sign(message, kp)
		fmt.Printf("Your signature is: %s \n", l)
	} else {
		fmt.Println("Please pass in a message to be signed!")
	}
}
