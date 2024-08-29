package core

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var DefaultOptions = &Options{
	SaltLength:  32,
	KeyLength:   32,
	Iterations:  4,
	Memory:      256 * 1024,
	Parallelism: 6,
}

func TestCreateHash(t *testing.T) {
	hashPattern := regexp.MustCompile(`^\$argon2id\$v=19\$m=[0-9]{1,8},t=[0-9]{1,2},p=[0-9]{1,2}\$[A-Za-z0-9+/]{43}\$[A-Za-z0-9+/]{43}$`)
	hash1, err := CreateHash("mYP4$sw0rD", DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}

	hash2, err := CreateHash("mYP4$sw0rD", DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}

	if !hashPattern.MatchString(hash1) {
		t.Errorf("Incorrect hash format: %q", hash1)
	}

	if !hashPattern.MatchString(hash2) {
		t.Errorf("Incorrect hash format: %q", hash2)
	}

	if strings.Compare(hash1, hash2) == 0 {
		t.Error("Hash must be unique.")
	}
}

func TestDecodeHash(t *testing.T) {
	hash, err := CreateHash("Pa$sw0rDu", DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	_, _, options, err := DecodeHash(hash)
	if err != nil {
		t.Fatal(err)
	}

	if *DefaultOptions != *options {
		t.Fatalf("expect %#v got %#v", *DefaultOptions, *options)
	}
}

func TestVerifyHash(t *testing.T) {
	hash, err := CreateHash("Pa$sw0rDu", DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}

	ok, options, err := VerifyHash("Pa$sw0rDu", hash)
	if err != nil {
		fmt.Println("PRINT FATAL")
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("expected matched password.")
	}

	if *DefaultOptions != *options {
		t.Fatalf("expect %#v got %#v", *DefaultOptions, *options)
	}
}
