package utils

import (
	"log"
	"os"
	"crypto/sha512"
	"encoding/hex"
	"math/rand"
)

func Check(e error) {
	if e != nil {
		log.Fatal(e)
		panic(e)
	}
}

func SoftCheck(e error){
	if e != nil {
		log.Println(e)
	}
}

func Kill(code int) {
	os.Exit(code)
}

func SHA512 (plaintext string) string{
	sha_512 := sha512.New()
	sha_512.Write([]byte(plaintext))
	return hex.EncodeToString(sha_512.Sum(nil))
}

func RandomString(n int) string {
    var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

    s := make([]rune, n)
    for i := range s {
        s[i] = letters[rand.Intn(len(letters))]
    }
    return string(s)
}
