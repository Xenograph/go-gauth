package gauth

import (
	"testing"
)

func TestTOTP(t *testing.T) {
	secret := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	timeIntervals := int64(47156746)
	correctOTP := "109431"
	otp, err := computeTOTP(secret, timeIntervals)
	if err != nil {
		t.Errorf("computeTOTP returns an error for valid input: %s", err.Error())
	}
	if otp != correctOTP {
		t.Errorf("TOTP(%s, %d) = %s, what %s", secret, timeIntervals, otp, correctOTP)
	}
}
