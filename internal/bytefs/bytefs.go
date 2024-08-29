package bytefs

import (
	"fmt"
	"os"
)

func ReadFile(filepath string) ([]byte, error) {
	dat, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return dat, nil
}

func WriteFile(filepath string, data []byte) error {
	fmt.Println("File written.")
	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return err
	}
	return nil
}
