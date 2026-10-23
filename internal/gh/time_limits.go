package gh

import "math"

// TTL is stored as an absolute Unix-second deadline. Never let addition wrap.
func secondsDeadline(start int64, seconds int) (int64, bool) {
	if seconds < 0 || start > math.MaxInt64-int64(seconds) {
		return 0, false
	}
	return start + int64(seconds), true
}

// Compare seconds directly rather than converting to nanoseconds or adding a
// duration to a timestamp. Both operations can overflow for long-lived grants.
func secondsElapsed(start int64, seconds int, at int64) bool {
	return seconds >= 0 && at >= start && uint64(at)-uint64(start) >= uint64(seconds)
}
