// Atlant's certificate agent is independent of the VPN and panel processes.
package main

import (
	"atlant.local/protocol/certificates"
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config := flag.String("config", "/var/lib/atlant-control/certificates/config.json", "Private certificate agent configuration")
	check := flag.Bool("check", false, "Validate configuration without issuing certificates or binding ports")
	flag.Parse()
	if *check {
		if _, _, err := certificates.LoadAgentConfig(*config); err != nil {
			log.Fatal(err)
		}
		log.Print("Certificate agent configuration is valid; no CA request performed")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := certificates.RunConfigFile(ctx, *config); err != nil {
		log.Fatal(err)
	}
}
