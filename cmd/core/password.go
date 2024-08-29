package core

import (
	crand "crypto/rand"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand/v2"
	"strings"
)

type Password struct {
	Text          string
	Charset       string
	Length        int
	CharsetLength int
	Entropy       float64
	HasUpper      bool
	HasLower      bool
	HasDigit      bool
	HasSymbol     bool
}

// TODO:
// create & persist database file
// encrypt/decrypt database file

// Generate random string
func (p *Password) Generate() {
	var password strings.Builder

	if !p.HasUpper && !p.HasLower && !p.HasDigit && !p.HasSymbol {
		return
	}

	if p.HasUpper {
		p.CharsetLength += 26
		p.Charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}

	if p.HasLower {
		p.CharsetLength += 26
		p.Charset += "abcdefghijklmnopqrstuvwxyz"
	}

	if p.HasDigit {
		p.CharsetLength += 10
		p.Charset += "0123456789"
	}

	if p.HasSymbol {
		p.Charset += "/\\~`!@#$%^&*-_+=|{}[]();:'<>,.?\""
		p.CharsetLength += 32
	}

	for i := 0; i < p.Length; i++ {
		index, _ := crand.Int(crand.Reader, big.NewInt(int64(p.CharsetLength)))
		password.WriteString(string(p.Charset[index.Int64()]))
	}

	p.Text = password.String()

	entropy := math.Log2(math.Pow(float64(p.CharsetLength), float64(p.Length)))
	p.Entropy = math.Round(entropy*100) / 100

	shuff := []rune(password.String())
	mrand.Shuffle(len(shuff), func(i, j int) {
		shuff[i], shuff[j] = shuff[j], shuff[i]
	})

	p.Text = string(shuff)
}

// Password struct string representation
func (p *Password) String() string {
	if len(p.Text) == 0 {
		return p.Text
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Password = %v Charset = %v Entropy = %v bits", p.Text, p.CharsetLength, p.Entropy)
	return sb.String()
}
