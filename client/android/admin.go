//go:build android || (linux && atlanttest)

package atlant

import "atlant.local/remoteadmin"

func AdminProbe(host string, port int) (string, error) { return remoteadmin.Probe(host, port) }
func AdminBegin(request string) (string, error)        { return remoteadmin.Begin(request) }
func AdminStatus(id string) string                     { return remoteadmin.Status(id) }
func AdminClose(id string)                             { remoteadmin.Close(id) }
func AdminCall(id, request string) (string, error)     { return remoteadmin.Call(id, request) }
