package utils

import "time"

// Now returns the current UTC time (for consistent DB timestamps)
func Now() time.Time {
	return time.Now().UTC()
}
