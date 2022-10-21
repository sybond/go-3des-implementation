/*
Sample implementation of 3DES using double length key.

Ref: https://www.cs.sjsu.edu/~stamp/CS265/SecurityEngineering/chapter5_SE/tripleDES.html

*/

package main

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
)

func EncryptTripleDES(key, data, iv []byte) []byte {
	if len(key) == 16 {
		key = append(key, key[:8]...)
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)
	return ciphertext
}

func DecryptTripleDES(key, data, iv []byte) []byte {
	if len(key) == 16 {
		key = append(key, key[:8]...)
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)
	return ciphertext
}

func main() {
	key, _ := hex.DecodeString("1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C")
	iv, _ := hex.DecodeString("0000000000000000")
	data, _ := hex.DecodeString("313233343536373839303132333435363d3132333435363738393031323334353637383930FFFFFF")
	encrypted_data := EncryptTripleDES(key, data, iv)
	decrypted_data := DecryptTripleDES(key, encrypted_data, iv)
	fmt.Printf("Clear      : %x\n", data)
	fmt.Printf("Encrypted  : %x\n", encrypted_data)
	fmt.Printf("Dencrypted : %x\n", decrypted_data)

}
