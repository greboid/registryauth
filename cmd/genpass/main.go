package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	state, err := term.GetState(syscall.Stdin)
	if err != nil {
		log.Printf("Unable to get terminal state: %s", err)
	}
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer func() {
		signal.Stop(signalChan)
		err = term.Restore(syscall.Stdin, state)
		if err != nil {
			log.Printf("Unable to restore terminal state: %s", err)
		}
	}()
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
