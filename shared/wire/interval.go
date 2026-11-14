package wire

import (
	"math/rand/v2"
	"time"
)

// ProbeInterval gives each carrier a stable interval within a bounded range.
// Call it during setup, outside the packet and application write paths.
func ProbeInterval(minimum, maximum time.Duration) time.Duration {
	if maximum <= minimum {
		return minimum
	}
	return minimum + rand.N(maximum-minimum)
}
