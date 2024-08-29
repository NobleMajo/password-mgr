package main

import (
	"encoding/hex"
	"fmt"

	"github.com/aminerwx/password-mgr/cmd/core"
	"github.com/aminerwx/password-mgr/internal/bytefs"
)

func main() {
	var pwd core.Password
	pwd.Length = 20
	pwd.HasUpper = true
	pwd.HasLower = true
	pwd.HasDigit = true
	pwd.HasSymbol = true
	pwd.Generate()
	fmt.Println(pwd.Text)

	// KDF options
	options := &core.Options{
		SaltLength:  32,
		KeyLength:   32,
		Iterations:  10,
		Memory:      128 * 1024,
		Parallelism: 2,
	}

	hash, err := core.CreateHash("password", options)
	maybe(err)

	match, _, err := core.VerifyHash("password", hash)
	maybe(err)

	k, _, _, err := core.DecodeHash(hash)
	maybe(err)

	if match {
		fmt.Println("Password is matching.")
		ciphertxt, err := core.EncryptAES([]byte("SecretMsg"), []byte(k))
		maybe(err)

		plaintext, err := core.DecryptAES(ciphertxt, []byte(k))
		maybe(err)

		cipher := hex.EncodeToString(ciphertxt)
		plain := string(plaintext)
		data := fmt.Sprintf("Secret Key: \n\t%v\nAES-256:\n\tciphertext: \n\t\t%v\n\tplaintext: \n\t\t%v\n", hash, cipher, plain)
		bytefs.WriteFile("./out/data", []byte(data))
	} else {
		fmt.Println("Incorrect password.")
	}
}

func maybe(err error) {
	if err != nil {
		panic(err)
	}
}
