package main

import "fmt"

func maskEnvValue(name, value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return fmt.Sprintf("%s=\"\" (length=0)", name)
	}
	masked := string(runes[0]) + "***"
	return fmt.Sprintf("%s=%s (length=%d)", name, masked, len(runes))
}