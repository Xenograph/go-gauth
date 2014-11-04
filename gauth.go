package gauth

import (
	"math"
	"strconv"
)

// Returns a boolean indicating if the provided otp string is valid for
// the provided secret at the current time. The secret should be base32
// encoded.
func ValidateOTP(otp, secret string) bool {
	correctOTP, err := GetOTP(secret)
	return (otp == correctOTP) && (err == nil)
}

// Returns a string containing the TOTP token associated with
// the provided secret at the current time. The secret should be
// base32 encoded.
func GetOTP(secret string) (string, error) {
	return computeTOTP(secret, timestamp())
}

// Generates a cryptographically secure base32 string that is the
// proper length for a secret to be used with Google Authenticator.
// This can be used for generating new secrets.
func GenerateSecret() (string, error) {
	return generateBase32CryptoString(SECRET_LENGTH)
}

func computeTOTP(secret string, time int64) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}

	msg := encodeTime(time)
	hash := computeHMAC(msg, key)

	offset := hash[len(hash)-1] & 0x0F
	binary := (int(hash[offset]&0x7F) << 24) |
		(int(hash[offset+1]&0xFF) << 16) |
		(int(hash[offset+2]&0xFF) << 8) |
		int(hash[offset+3]&0xFF)
	otp := binary % int(math.Pow10(RETURN_DIGITS))

	result := strconv.Itoa(otp)
	for len(result) < RETURN_DIGITS {
		result = "0" + result
	}

	return result, nil
}
