package modules

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	reHexToken    = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	reISO8601     = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?`)
	reUnixEpoch   = regexp.MustCompile(`\b(1[0-9]{9}|2[0-4][0-9]{8})\b`)
	reHTMLComment = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// NormaliseBody removes dynamic content like timestamps and tokens to facilitate comparison.
func NormaliseBody(body string) string {
	body = reHTMLComment.ReplaceAllString(body, "")
	body = reHexToken.ReplaceAllString(body, " TOKEN ")
	body = reISO8601.ReplaceAllString(body, " TIMESTAMP ")
	body = reUnixEpoch.ReplaceAllString(body, " TIMESTAMP ")
	return strings.ToLower(body)
}

// Tokenise breaks a string into a set of unique words.
func Tokenise(body string) map[string]struct{} {
	tokens := make(map[string]struct{})
	f := func(c rune) bool {
		return unicode.IsSpace(c) || unicode.IsPunct(c)
	}
	words := strings.FieldsFunc(body, f)
	for _, w := range words {
		if len(w) >= 2 {
			tokens[w] = struct{}{}
		}
	}
	return tokens
}

// JaccardSimilarity calculates the similarity ratio between two sets of tokens.
func JaccardSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	intersection := 0
	for k := range a {
		if _, ok := b[k]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}
