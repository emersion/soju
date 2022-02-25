package soju

import (
	"testing"
)

func TestIsHighlight(t *testing.T) {
	nick := "SojuUser"
	testCases := []struct {
		name string
		text string
		hl   bool
	}{
		{"noContains", "hi there Soju User!", false},
		{"middle", "hi there SojuUser!", true},
		{"start", "SojuUser: how are you doing?", true},
		{"end", "maybe ask SojuUser", true},
		{"inWord", "but OtherSojuUserSan is a different nick", false},
		{"startWord", "and OtherSojuUser is another different nick", false},
		{"endWord", "and SojuUserSan is yet a different nick", false},
		{"underscore", "and SojuUser_san has nothing to do with me", false},
		{"zeroWidthSpace", "writing S\u200BojuUser shouldn't trigger a highlight", false},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			hl := isHighlight(tc.text, nick)
			if hl != tc.hl {
				t.Errorf("isHighlight(%q, %q) = %v, but want %v", tc.text, nick, hl, tc.hl)
			}
		})
	}
}
