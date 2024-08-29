package randomb

import (
	"testing"
)

func TestRandomBytes(t *testing.T) {
	randomBytes, err := RandomBytes(5)
	if err != nil {
		t.Fatal(err)
	}

	if len(randomBytes) != 5 {
		t.Fatalf("expected %v got %v\n", 5, len(randomBytes))
	}
}
