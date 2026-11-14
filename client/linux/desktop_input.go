package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
)

// The desktop keeps the same pipe open for shutdown after this configuration frame.
func readDesktopInput(input io.Reader, cfg *Config) (*bufio.Scanner, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	if !scanner.Scan() {
		return nil, errors.New("missing or oversized desktop configuration")
	}
	line := scanner.Bytes()
	if json.Unmarshal(line, cfg) != nil {
		return nil, errors.New("invalid desktop configuration")
	}
	var extra struct {
		DNS        string `json:"dns"`
		BlockIPv6  bool   `json:"block_ipv6"`
		KillSwitch bool   `json:"kill_switch"`
		AllowLAN   bool   `json:"allow_lan"`
		UpMbps     int    `json:"up_mbps"`
		DownMbps   int    `json:"down_mbps"`
		RouteMode  string `json:"route_mode"`
	}
	if json.Unmarshal(line, &extra) != nil {
		return nil, errors.New("invalid desktop configuration")
	}
	if extra.KillSwitch || extra.AllowLAN || extra.RouteMode != "" && extra.RouteMode != "all" {
		return nil, errors.New("desktop configuration requests protection or routing options not implemented by this Linux core")
	}
	if extra.DNS != "" {
		cfg.TunDNS = extra.DNS
	}
	cfg.DisableIPv6 = extra.BlockIPv6
	return scanner, nil
}
