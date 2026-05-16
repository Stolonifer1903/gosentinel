package modules

import (
	"strings"
	"testing"
)

func TestNormaliseBody_UnixEpochReplaced(t *testing.T) {
	input := "ts=1698393600"
	out := NormaliseBody(input)
	if !strings.Contains(out, "timestamp") {
		t.Errorf("Expected timestamp replacement, got %q", out)
	}
}

func TestNormaliseBody_LargeIDNotReplaced(t *testing.T) {
	input := "user_id=10000000000" // 11 digits
	out := NormaliseBody(input)
	if strings.Contains(out, "timestamp") {
		t.Errorf("Expected large ID to NOT be replaced, got %q", out)
	}
	if !strings.Contains(out, "10000000000") {
		t.Errorf("Expected large ID to be preserved, got %q", out)
	}
}

func TestNormaliseBody_FutureTimestampReplaced(t *testing.T) {
	input := "ts=2400000000" // 10 digits, year 2046
	out := NormaliseBody(input)
	if !strings.Contains(out, "timestamp") {
		t.Errorf("Expected future timestamp replacement, got %q", out)
	}
}

func TestNormaliseBody_SmallNumberPreserved(t *testing.T) {
	input := "id=42"
	out := NormaliseBody(input)
	if out != "id=42" {
		t.Errorf("Expected small number to be preserved, got %q", out)
	}
}

func TestNormaliseBody_HexTokenReplaced(t *testing.T) {
	input := "token=abcdef1234567890abcdef1234567890"
	out := NormaliseBody(input)
	// Output replaces hex token with " TOKEN " which is lowered to " token "
	if !strings.Contains(out, "token") {
		t.Errorf("Expected hex token replacement, got %q", out)
	}
}

func TestNormaliseBody_HTMLCommentStripped(t *testing.T) {
	input := "hello <!-- secret --> world"
	out := NormaliseBody(input)
	if strings.Contains(out, "secret") {
		t.Errorf("Expected HTML comment to be stripped, got %q", out)
	}
}
