package main

import (
	"fmt"
	"log"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	fmt.Print("Enter Password: ")
	bytePassword, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		log.Printf("Unable to read password.")
	}
	bytePassword, err = bcrypt.GenerateFromPassword(bytePassword, 7)
	if err != nil {
		log.Printf("Unable to generate password: %s", err)
	}
	fmt.Println()
	fmt.Printf("%s\n", bytePassword)
}
