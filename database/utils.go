package database

import "strings"

func startsHexColor(s string) bool {
	if len(s) < 6 {
		return false
	}
	for _, r := range s[:6] {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func stripANSI(s string) string {
	if !strings.ContainsAny(s, "\x02\x1D\x1F\x1E\x11\x16\x0F\x03\x04") {
		// Fast case: no formatting
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch b {
		case '\x02', '\x1D', '\x1F', '\x1E', '\x11', '\x16', '\x0F':
		case '\x03':
			if len(s) <= i+1 || s[i+1] < '0' || s[i+1] > '9' {
				break
			}
			i++
			if len(s) > i+1 && s[i+1] >= '0' && s[i+1] <= '9' {
				i++
			}
			if len(s) > i+2 && s[i+1] == ',' && s[i+2] >= '0' && s[i+2] <= '9' {
				i += 2
				if len(s) > i+1 && s[i+1] >= '0' && s[i+1] <= '9' {
					i++
				}
			}
		case '\x04':
			if !startsHexColor(s[i+1:]) {
				break
			}
			i += 6
			if len(s) > i+1 && s[i+1] == ',' && startsHexColor(s[i+2:]) {
				i += 7
			}
		default:
			sb.WriteByte(b)
		}
	}
	return sb.String()
}
