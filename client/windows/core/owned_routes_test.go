package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestOwnedRouteDeletionIsScopedToGatewayAndInterface(t *testing.T) {
	route := routeSpec{"0.0.0.0", "128.0.0.0", "172.19.0.1", "42"}
	expected := []string{"delete", "0.0.0.0", "mask", "128.0.0.0", "172.19.0.1", "IF", "42"}
	if !reflect.DeepEqual(route.args("delete"), expected) {
		t.Fatalf("unscoped deletion: %v", route.args("delete"))
	}
}

func TestExistingRouteIsNeverClaimedOrDeleted(t *testing.T) {
	routeMu.Lock()
	oldRunner, oldExists, oldRoutes, oldClosing := runRoute, routeExists, ownedRoutes, routesClosing
	ownedRoutes = make(map[routeSpec]bool)
	routesClosing = false
	calls := 0
	runRoute = func(...string) error { calls++; return errors.New("already exists") }
	routeExists = func(routeSpec) bool { return true }
	routeMu.Unlock()
	defer func() {
		routeMu.Lock()
		runRoute, routeExists, ownedRoutes, routesClosing = oldRunner, oldExists, oldRoutes, oldClosing
		routeMu.Unlock()
	}()
	route := routeSpec{"203.0.113.1", "255.255.255.255", "192.168.0.1", "3"}
	if err := addOwnedRoute(route); err != nil {
		t.Fatal(err)
	}
	removeOwnedRoute(route)
	if calls != 1 || len(ownedRoutes) != 0 {
		t.Fatal("cleanup tried to delete somebody else's route")
	}
}

func TestExactRouteMatchRejectsDifferentInterface(t *testing.T) {
	route := routeSpec{"203.0.113.1", "255.255.255.255", "192.168.0.1", "3"}
	table := "203.0.113.1 255.255.255.255 192.168.0.1 192.168.0.9 1\n"
	if exactRoutePresent(table, route, []string{"192.168.0.8"}) {
		t.Fatal("accepted another interface")
	}
	if !exactRoutePresent(table, route, []string{"192.168.0.9"}) {
		t.Fatal("did not find exact route")
	}
}
