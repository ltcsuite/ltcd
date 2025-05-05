package scrypt

import (
	"runtime"
	"testing"

	scrypt2 "golang.org/x/crypto/scrypt"
)

func scryptGeneric(x []byte) []byte {
	result, _ := scrypt2.Key(x, x, 1024, 1, 1, 32)
	return result
}

func BenchmarkARM64Implementation(b *testing.B) {
	password := []byte("benchmark password")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scrypt(password)
	}
}

func BenchmarkGenericImplementation(b *testing.B) {
	password := []byte("benchmark password")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scryptGeneric(password)
	}
}

// BenchmarkComparisonWithVariousSizes benchmarks both implementations
// with different input sizes
func BenchmarkComparisonWithVariousSizes(b *testing.B) {
	// Create test inputs of different sizes
	inputs := []struct {
		name string
		size int
	}{
		{"8B", 8},
		{"32B", 32},
		{"64B", 64},
		{"128B", 128},
	}

	for _, tc := range inputs {
		// Generate input of specified size
		input := make([]byte, tc.size)
		for i := range input {
			input[i] = byte(i % 256)
		}

		// Benchmark ARM64 implementation
		b.Run("ARM64_"+tc.name, func(b *testing.B) {
			// Skip if not on ARM64
			if isARM64() {
				for i := 0; i < b.N; i++ {
					_ = scrypt(input)
				}
			} else {
				b.Skip("Skipping ARM64 test on non-ARM64 architecture")
			}
		})

		// Benchmark generic implementation
		b.Run("Generic_"+tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = scryptGeneric(input)
			}
		})
	}
}

func isARM64() bool {
	return runtime.GOARCH == "arm64"
}
