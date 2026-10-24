package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed panel/*
var managementPanel embed.FS

func managementPanelHandler() http.Handler {
	assets, _ := fs.Sub(managementPanel, "panel")
	files := http.StripPrefix("/panel/", http.FileServer(http.FS(assets)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}
