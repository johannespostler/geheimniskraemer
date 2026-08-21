// Command gk is Geheimniskrämer: a self-hosted, passkey-only password manager.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "invite":
		err = cmdInvite(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gk:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  gk serve  [-listen addr] [-db path] [-origin url]   start the server
  gk invite [-db path] <username>                     create a registration invite
`)
}
