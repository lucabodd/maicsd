package utils

import (
	"log"
	"os"
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
