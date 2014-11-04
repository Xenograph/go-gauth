package gauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"math/big"
	"time"
)

func timestamp() int64 {
	return time.Now().Unix() / 30
}

func computeHMAC(data, secret []byte) []byte {
	mac := hmac.New(sha1.New, secret)
	mac.Write(data)
	return mac.Sum(nil)
}

func decodeSecret(secret string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(secret)
}

func encodeSecret(secret []byte) string {
	return base32.StdEncoding.EncodeToString(secret)
}

func encodeTime(time int64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, time)
	return buf.Bytes()
}

func generateBase32CryptoString(length int) (string, error) {
	str := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	buf := &bytes.Buffer{}
	for i := 0; i < length; i++ {
		choice, err := rand.Int(rand.Reader, big.NewInt(int64(len(str))))
		if err != nil {
			return "", err
		}
		buf.WriteString(string(str[uint8(choice.Int64())]))
	}
	return buf.String(), nil
}
