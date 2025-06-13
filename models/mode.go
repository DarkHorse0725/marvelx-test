package models

import "errors"

type CryptoMode string

const (
	ClassicalMode   CryptoMode = "classical"
	QuantumSafeMode CryptoMode = "quantum-safe"
)

var ValidCryptoModes = []CryptoMode{
	ClassicalMode,
	QuantumSafeMode,
}

func IsValidCryptoMode(input string) bool {
	for _, mode := range ValidCryptoModes {
		if input == string(mode) {
			return true
		}
	}
	return false
}

func ToCryptoMode(mode string) (CryptoMode, error) {
	switch mode {
	case string(ClassicalMode):
		return ClassicalMode, nil
	case string(QuantumSafeMode):
		return QuantumSafeMode, nil
	default:
		return "", errors.New("invalid crypto mode")
	}
}
