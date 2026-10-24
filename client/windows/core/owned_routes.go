package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type routeSpec struct{ destination, mask, gateway, ifIndex string }

func (r routeSpec) args(operation string) []string {
	args := []string{operation, r.destination, "mask", r.mask, r.gateway}
	if operation == "add" {
		args = append(args, "metric", "1")
	}
	return append(args, "IF", r.ifIndex)
}

var routeMu sync.Mutex
var ownedRoutes = make(map[routeSpec]bool)
var routesClosing bool
var removedDefaultRoute *routeSpec
var routeExists = func(route routeSpec) bool {
	index, err := strconv.Atoi(route.ifIndex)
	if err != nil {
		return false
	}
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return false
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	var interfaceIPs []string
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil {
			interfaceIPs = append(interfaceIPs, ip.String())
		}
	}
	output, err := exec.Command("route", "print", "-4", route.destination).Output()
	return err == nil && exactRoutePresent(string(output), route, interfaceIPs)
}

func exactRoutePresent(table string, route routeSpec, interfaceIPs []string) bool {
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != route.destination || fields[1] != route.mask || fields[2] != route.gateway {
			continue
		}
		for _, ip := range interfaceIPs {
			if fields[3] == ip {
				return true
			}
		}
	}
	return false
}

var runRoute = func(args ...string) error {
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route command failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func addOwnedRoute(route routeSpec) error {
	routeMu.Lock()
	defer routeMu.Unlock()
	if routesClosing {
		return fmt.Errorf("VPN routes are shutting down")
	}
	if route.ifIndex == "" || route.gateway == "" {
		return fmt.Errorf("route requires an interface and gateway")
	}
	if _, exists := ownedRoutes[route]; exists {
		return nil
	}
	if err := runRoute(route.args("add")...); err != nil {
		// An existing exact host route already excludes the server from TUN.
		// Reuse it without recording ownership or deleting it during cleanup.
		if routeExists(route) {
			return nil
		}
		return err
	}
	ownedRoutes[route] = false
	return nil
}

func removeOwnedRoute(route routeSpec) {
	routeMu.Lock()
	defer routeMu.Unlock()
	if pinned, owned := ownedRoutes[route]; owned && !pinned {
		_ = runRoute(route.args("delete")...)
		delete(ownedRoutes, route)
	}
}

func pinOwnedRoute(route routeSpec) {
	routeMu.Lock()
	defer routeMu.Unlock()
	if _, owned := ownedRoutes[route]; owned {
		ownedRoutes[route] = true
	}
}
