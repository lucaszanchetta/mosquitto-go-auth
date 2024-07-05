package hashing

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
)

type pbkdf2Hasher struct {
	saltSize     int
	iterations   int
	algorithm    string
	saltEncoding string
	keyLen       int
}

func NewPBKDF2Hasher(saltSize int, iterations int, algorithm string, saltEncoding string, keyLen int) pbkdf2Hasher {
	return pbkdf2Hasher{
		saltSize:     saltSize,
		iterations:   iterations,
		algorithm:    algorithm,
		saltEncoding: saltEncoding,
		keyLen:       keyLen,
	}
}

func (h pbkdf2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("read random bytes error: %s", err)
	}

	for i := 0; i < len(salt); i++ {
		if salt[i] == 36 { // If the byte is a dollar sign ('$')
			n, err := rand.Int(rand.Reader, big.NewInt(35))
			if err != nil {
				return "", fmt.Errorf("read random byte error: %s", err)
			}
			salt[i] = byte(n.Int64())
		}
	}

	log.Infof("Generated salt (raw): %v", salt)
	saltEncoded := base64.RawStdEncoding.EncodeToString(salt) // No padding
	log.Infof("Generated salt (base64): %s", saltEncoded)

	return h.hashWithSalt(password, salt, h.iterations, h.algorithm, h.keyLen), nil
}

func (h pbkdf2Hasher) Compare(password string, passwordHash string) bool {
	hashSplit := strings.Split(passwordHash, "$")

	if len(hashSplit) != 4 {
		log.Errorf("invalid PBKDF2 hash supplied, expected length 4, got: %d", len(hashSplit))
		log.Error(hashSplit)
		return false
	}

	var (
		err            error
		algorithm      string
		iterations     int
		hashedPassword []byte
		salt           []byte
		keyLen         int
	)

	if hashSplit[0] == "pbkdf2_sha256" {
		algorithm = "sha256"
		// get iterations number
		iterations, err = strconv.Atoi(hashSplit[1])
		if err != nil {
			log.Errorf("iterations error: %s", err)
			log.Error(hashSplit)
			return false
		}

		salt, err = base64.RawStdEncoding.DecodeString(hashSplit[2]) // No padding
		if err != nil {
			log.Errorf("base64 salt error: %s", err)
			log.Errorf("Base64 salt: %s", hashSplit[2])
			log.Error(hashSplit)
			return false
		}
		log.Infof("Decoded salt (raw): %v", salt)

		hashedPassword, err = base64.RawStdEncoding.DecodeString(hashSplit[3]) // No padding
		if err != nil {
			log.Errorf("base64 hash decoding error: %s", err)
			log.Errorf("Base64 hash: %s", hashSplit[3])
			log.Error(hashSplit)
			return false
		}
		keyLen = len(hashedPassword)

	} else {
		log.Errorf("invalid PBKDF2 hash supplied, unrecognized format \"%s\"", hashSplit[0])
		return false
	}

	newHash := h.hashWithSalt(password, salt, iterations, algorithm, keyLen)
	newHashSplit := strings.Split(newHash, "$")
	if len(newHashSplit) != 4 {
		log.Errorf("new hash generated with unexpected length: %d", len(newHashSplit))
		return false
	}

	newHashedPassword, err := base64.RawStdEncoding.DecodeString(newHashSplit[3])
	if err != nil {
		log.Errorf("base64 hash decoding error: %s", err)
		return false
	}

	log.Infof("db hash: %v", hashSplit)
	log.Infof("generated: %v", newHashSplit)
	return h.compareBytes(hashedPassword, newHashedPassword)
}

func (h pbkdf2Hasher) compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		if b[i] != x {
			return false
		}
	}
	return true
}

func (h pbkdf2Hasher) hashWithSalt(password string, salt []byte, iterations int, algorithm string, keylen int) string {
	shaHash := sha512.New
	if algorithm == "sha256" {
		shaHash = sha256.New
	}

	hashed := pbkdf2.Key([]byte(password), salt, iterations, keylen, shaHash)

	var buffer bytes.Buffer

	buffer.WriteString("pbkdf2_sha256$")
	buffer.WriteString(strconv.Itoa(iterations))
	buffer.WriteString("$")
	buffer.WriteString(base64.RawStdEncoding.EncodeToString(salt)) // No padding
	buffer.WriteString("$")
	buffer.WriteString(base64.RawStdEncoding.EncodeToString(hashed)) // No padding

	return buffer.String()
}
