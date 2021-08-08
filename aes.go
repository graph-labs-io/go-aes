package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/mergermarket/go-pkcs7"

	_ "github.com/joho/godotenv/autoload"
)

func AesEnryptionHelper(plaintext string, hexKey string) (ciphertext string, err error) {
	byteKey, decodeErr := hex.DecodeString(hexKey)
	if decodeErr != nil {
		return "", decodeErr
	}

	aesEncryptedString, encryptionErr := Encrypt(plaintext, byteKey)
	if encryptionErr != nil {
		return "", encryptionErr
	}

	return aesEncryptedString, nil
}

func AesDecryptionHelper(ciphertext string, hexKey string) (plaintext string, err error) {
	byteKey, decodeErr := hex.DecodeString(hexKey)
	if decodeErr != nil {
		return "", decodeErr
	}

	aesDecryptedString, decryptionErr := Decrypt(ciphertext, byteKey)
	if decryptionErr != nil {
		return "", decryptionErr
	}

	return aesDecryptedString, nil
}

func Encrypt(unencrypted string, key []byte) (string, error) {
	plainText := []byte(unencrypted)
	plainText, err := pkcs7.Pad(plainText, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf(`plainText: "%s" has error`, plainText)
	}
	if len(plainText)%aes.BlockSize != 0 {
		return "", fmt.Errorf(`plainText: "%s" has the wrong block size`, plainText)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return fmt.Sprintf("%x", cipherText), nil
}

func Decrypt(encrypted string, key []byte) (string, error) {
	cipherText, decodeStringErr := hex.DecodeString(encrypted)
	if decodeStringErr != nil {
		return "", decodeStringErr
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		return "", fmt.Errorf("cipherText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	cipherText, unpadErr := pkcs7.Unpad(cipherText, aes.BlockSize)
	if unpadErr != nil {
		return "", unpadErr
	}

	cipherText = bytes.Trim(cipherText, "\x00")
	return fmt.Sprintf("%s", cipherText), nil
}
