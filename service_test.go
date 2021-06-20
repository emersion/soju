package soju

import (
	"testing"
)

func assertSplit(t *testing.T, input string, expected []string) {
	actual, err := splitWords(input)
	if err != nil {
		t.Errorf("%q: %v", input, err)
		return
	}
	if len(actual) != len(expected) {
		t.Errorf("%q: expected %d words, got %d\nexpected: %v\ngot: %v", input, len(expected), len(actual), expected, actual)
		return
	}
	for i := 0; i < len(actual); i++ {
		if actual[i] != expected[i] {
			t.Errorf("%q: expected word #%d to be %q, got %q\nexpected: %v\ngot: %v", input, i, expected[i], actual[i], expected, actual)
		}
	}
}

func TestSplit(t *testing.T) {
	assertSplit(t, "  ch 'up' #soju    'relay'-det\"ache\"d  message  ", []string{
		"ch",
		"up",
		"#soju",
		"relay-detached",
		"message",
	})
	assertSplit(t, "net update \\\"free\\\"node -pass 'political \"stance\" desu!' -realname '' -nick lee", []string{
		"net",
		"update",
		"\"free\"node",
		"-pass",
		"political \"stance\" desu!",
		"-realname",
		"",
		"-nick",
		"lee",
	})
	assertSplit(t, "Omedeto,\\ Yui! ''", []string{
		"Omedeto, Yui!",
		"",
	})

	if _, err := splitWords("end of 'file"); err == nil {
		t.Errorf("expected error on unterminated single quote")
	}
	if _, err := splitWords("end of backquote \\"); err == nil {
		t.Errorf("expected error on unterminated backquote sequence")
	}
}
