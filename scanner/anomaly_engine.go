package scanner

import (
	"math"
	"strings"
)

// CalculateShannonEntropy measures the randomness of a string.
// High entropy in DNS queries often indicates a Domain Generation Algorithm (DGA) used by malware.
func CalculateShannonEntropy(data string) float64 {
	if data == "" {
		return 0
	}

	// Remove TLDs for more accurate DGA scoring (e.g. .com, .net)
	parts := strings.Split(data, ".")
	if len(parts) > 1 {
		data = strings.Join(parts[:len(parts)-1], "")
	}

	frequencies := make(map[rune]float64)
	for _, char := range data {
		frequencies[char]++
	}

	var entropy float64
	length := float64(len(data))

	for _, freq := range frequencies {
		p := freq / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsDGA flags a domain as potentially malicious if its entropy exceeds a threshold.
// Normal domains like "google" have low entropy (~2.2).
// DGA domains like "vweiojweiorjwe.com" have high entropy (> 3.8).
func IsDGA(domain string) (bool, float64) {
	// Skip very short domains
	if len(domain) < 8 {
		return false, 0
	}
	
	entropy := CalculateShannonEntropy(domain)
	if entropy > 3.9 {
		return true, entropy
	}
	return false, entropy
}
