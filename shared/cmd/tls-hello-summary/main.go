package main

import (
	"atlant.local/protocol/tlsaudit"
	"encoding/json"
	"os"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	summary, err := tlsaudit.Summarize(data)
	if err != nil {
		panic(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		panic(err)
	}
}
