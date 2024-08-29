package core

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/aminerwx/password-mgr/internal/randomb"
	"golang.org/x/crypto/argon2"
)

type Options struct {
	SaltLength  uint32
	KeyLength   uint32
	Iterations  uint32
	Memory      uint32
	Parallelism uint8
}

// Generate secret key and salt (argon2id KDF) from passphrase and options.
func GenerateKey(passphrase string, options *Options) (key, salt []byte, err error) {
	pwd := []byte(passphrase)
	if len(pwd) == 0 {
		return nil, nil, errors.New("empty passphrase")
	}

	salt, err = randomb.RandomBytes(options.SaltLength)
	if err != nil {
		return nil, nil, err
	}

	key = argon2.IDKey(pwd, salt, options.Iterations, options.Memory, options.Parallelism, options.KeyLength)
	return key, salt, nil
}

// Create an argon2id string representation from secret key, salt and options
func CreateHash(passphrase string, options *Options) (hash string, err error) {
	key, salt, err := GenerateKey(passphrase, options)
	if err != nil {
		return "", err
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	hash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, options.Memory, options.Iterations, options.Parallelism, b64Salt, b64Key)
	return hash, nil
}

// Extract secret key, salt and options from argon2id string representation
func DecodeHash(hash string) (key, salt []byte, options *Options, err error) {
	values := strings.Split(hash, "$")
	if len(values) != 6 {
		return nil, nil, nil, errors.New("argon2id format is invalid")
	}
	if values[1] != "argon2id" {
		return nil, nil, nil, errors.New("invalid argon2 variant")
	}
	var version int
	_, err = fmt.Sscanf(values[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if argon2.Version != version {
		return nil, nil, nil, errors.New("invalid Argon2 version")
	}
	options = &Options{}
	fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &options.Memory, &options.Iterations, &options.Parallelism)

	salt, err = base64.RawStdEncoding.Strict().DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}
	options.SaltLength = uint32(len(salt))

	key, err = base64.RawStdEncoding.Strict().DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, err
	}
	options.KeyLength = uint32(len(key))

	return key, salt, options, nil
}

// Compare passphrase and decoded hash
func VerifyHash(passphrase string, hash string) (match bool, options *Options, err error) {
	key, salt, o, err := DecodeHash(hash)
	options = o
	if err != nil {
		return match, options, err
	}
	otherKey := argon2.IDKey([]byte(passphrase), salt, o.Iterations, o.Memory, o.Parallelism, o.KeyLength)

	keyLen := int32(len(key))
	otherKeyLen := int32(len(otherKey))
	if subtle.ConstantTimeEq(keyLen, otherKeyLen) == 0 {
		return false, options, nil
	}
	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, options, nil
	}

	return match, options, err
}
