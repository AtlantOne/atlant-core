package main

// GUI sends a complete profile and a private PBK pipe. Its DPAPI settings are
// not a core JSON config and must not be loaded as one before flag parsing.
func skipAutomaticConfig(args []string) bool {
	skip := false
	for _, arg := range args {
		switch arg {
		case "-no-config", "--no-config", "-no-config=true", "--no-config=true":
			skip = true
		case "-no-config=false", "--no-config=false":
			skip = false
		}
	}
	return skip
}
