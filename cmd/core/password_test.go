package core

import (
	"regexp"
	"testing"
)

type Test struct {
	name string
	got  string
	want bool
}

func hasCharset(str, charset string) bool {
	for _, s := range str {
		for _, c := range charset {
			if s == c {
				return true
			}
		}
	}
	return false
}

func TestGenerate(t *testing.T) {
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower := "abcdefghijklmnopqrstuvwxyz"
	number := "0123456789"
	symbol := "/\\~`!@#$%^&*-_+=|{}[]();:'<>,.?\""
	var pwd Password
	pwd.Length = 25
	pwd.Generate()
	p := pwd.Text

	if p != "" {
		t.Fatalf("got %v expect empty string\n", p)
	}

	pwd.HasUpper = true
	pwd.Generate()
	strUpper := pwd.Text
	match := hasCharset(strUpper, upper)

	if !match {
		t.Fatalf("expected %v got %v", true, match)
	}

	pwd.HasLower = true
	pwd.Generate()
	strLower := pwd.Text
	match = hasCharset(strLower, lower)

	if !match {
		t.Fatalf("expected %v got %v", true, match)
	}

	pwd.HasDigit = true
	pwd.Generate()
	strDigit := pwd.Text
	match = hasCharset(strDigit, number)

	if !match {
		t.Fatalf("input %v expected %v got %v", strDigit, true, match)
	}

	pwd.HasSymbol = true
	pwd.Generate()
	strSymbol := pwd.Text
	match = hasCharset(strSymbol, symbol)

	if !match {
		t.Fatalf("expected %v got %v", true, match)
	}

	p = pwd.Text
	if len(p) != 25 {
		t.Fatalf("got %v expected %v\n", len(p), 25)
	}
}

func TestString(t *testing.T) {
	var pwd Password
	pwd.Length = 10
	pwd.HasLower = true
	pwd.HasDigit = true
	pwd.Generate()
	pattern := regexp.MustCompile(`Password = [a-z0-9]{10} Charset = 36 Entropy = 51.7 bits`)

	if !pattern.MatchString(pwd.String()) {
		t.Fatal("String not matching")
	}
}
