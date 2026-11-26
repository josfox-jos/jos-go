// Command jos validates, seals, and inspects .jos (JSON Operating System) documents from the command line.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"josfox.cloud/jos"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "--version" || os.Args[1] == "version" {
		fmt.Printf("jos-go %s (josfox.cloud/jos)\n", jos.Version)
		return
	}
	cmd := os.Args[1]
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: jos <verify|seal|version> <file.jos>")
		os.Exit(2)
	}
	path := os.Args[2]
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch cmd {
	case "verify", "validate":
		art, err := jos.Verify(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
		fmt.Println(art)
	case "seal":
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sealed, art, err := jos.Seal(doc)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, sealed, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(art)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(2)
	}
}
