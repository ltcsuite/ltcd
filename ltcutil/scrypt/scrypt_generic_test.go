//go:build !arm64
// +build !arm64

package scrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestScrypt tests the scrypt implementation against
// Litecoin Core tests vectors
func TestScrypt(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "LitecoinVector1",
			input:    "020000004c1271c211717198227392b029a64a7971931d351b387bb80db027f270411e398a07046f7d4a08dd815412a8712f874a7ebf0507e3878bd24e20a3b73fd750a667d2f451eac7471b00de6659",
			expected: "00000000002bef4107f882f6115e0b01f348d21195dacd3582aa2dabd7985806",
		},
		{
			name:     "LitecoinVector2",
			input:    "0200000011503ee6a855e900c00cfdd98f5f55fffeaee9b6bf55bea9b852d9de2ce35828e204eef76acfd36949ae56d1fbe81c1ac9c0209e6331ad56414f9072506a77f8c6faf551eac7471b00389d01",
			expected: "00000000003a0d11bdd5eb634e08b7feddcfbbf228ed35d250daf19f1c88fc94",
		},
		{
			name:     "LitecoinVector3",
			input:    "02000000a72c8a177f523946f42f22c3e86b8023221b4105e8007e59e81f6beb013e29aaf635295cb9ac966213fb56e046dc71df5b3f7f67ceaeab24038e743f883aff1aaafaf551eac7471b0166249b",
			expected: "00000000000b40f895f288e13244728a6c2d9d59d8aff29c65f8dd5114a8ca81",
		},
		{
			name:     "LitecoinVector4",
			input:    "010000007824bc3a8a1b4628485eee3024abd8626721f7f870f8ad4d2f33a27155167f6a4009d1285049603888fe85a84b6c803a53305a8d497965a5e896e1a00568359589faf551eac7471b0065434e",
			expected: "00000000003007005891cd4923031e99d8e8d72f6e8e7edc6a86181897e105fe",
		},
		{
			name:     "LitecoinVector5",
			input:    "0200000050bfd4e4a307a8cb6ef4aef69abc5c0f2d579648bd80d7733e1ccc3fbc90ed664a7f74006cb11bde87785f229ecd366c2d4e44432832580e0608c579e4cb76f383f7f551eac7471b00c36982",
			expected: "000000000018f0b426a4afc7130ccb47fa02af730d345b4fe7c7724d3800ec8c",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert hex inputs to bytes
			input, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatalf("Failed to decode input: %v", err)
			}

			expectedBytes, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatalf("Failed to decode expected output: %v", err)
			}

			result := scrypt(input)

			// handle endianness
			reversedResult := make([]byte, len(result))
			for i := 0; i < len(result); i++ {
				reversedResult[i] = result[len(result)-1-i]
			}

			// compare scrypt() with vectors
			if !bytes.Equal(reversedResult, expectedBytes) {
				t.Errorf("Result mismatch for test %s\nGot:  %x\nWant: %x",
					tc.name, reversedResult, expectedBytes)
			} else {
				t.Logf("Test passed for %s", tc.name)
			}
		})
	}
}

// TestScryptCache tests the caching functionality
func TestScryptCache(t *testing.T) {
	// Clear the cache to start with a clean state
	SetCache(nil)

	// Use the first Litecoin test vector
	input, _ := hex.DecodeString("020000004c1271c211717198227392b029a64a7971931d351b387bb80db027f270411e398a07046f7d4a08dd815412a8712f874a7ebf0507e3878bd24e20a3b73fd750a667d2f451eac7471b00de6659")

	// First call should calculate the hash
	result1 := Scrypt(input)

	// Create a fake cache entry
	fakeOutput := make([]byte, 32)
	_, err := rand.Read(fakeOutput)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	// Set the cache with our fake value
	SetCache([]Hash{{Key: input, Val: fakeOutput}})

	// Second call should use the cached value
	result2 := Scrypt(input)

	// Verify that the second result is different from the first
	// and matches our fake value (proving it came from the cache)
	if bytes.Equal(result1, result2) {
		t.Errorf("Expected different result from cache, but got the same result")
	}

	if !bytes.Equal(result2, fakeOutput) {
		t.Errorf("Expected cached result, but got a different value")
	}
}

// BenchmarkScrypt benchmarks the scrypt implementation
func BenchmarkScrypt(b *testing.B) {
	testVectors := []string{
		"020000004c1271c211717198227392b029a64a7971931d351b387bb80db027f270411e398a07046f7d4a08dd815412a8712f874a7ebf0507e3878bd24e20a3b73fd750a667d2f451eac7471b00de6659",
		"0200000011503ee6a855e900c00cfdd98f5f55fffeaee9b6bf55bea9b852d9de2ce35828e204eef76acfd36949ae56d1fbe81c1ac9c0209e6331ad56414f9072506a77f8c6faf551eac7471b00389d01",
		"02000000a72c8a177f523946f42f22c3e86b8023221b4105e8007e59e81f6beb013e29aaf635295cb9ac966213fb56e046dc71df5b3f7f67ceaeab24038e743f883aff1aaafaf551eac7471b0166249b",
		"010000007824bc3a8a1b4628485eee3024abd8626721f7f870f8ad4d2f33a27155167f6a4009d1285049603888fe85a84b6c803a53305a8d497965a5e896e1a00568359589faf551eac7471b0065434e",
		"0200000050bfd4e4a307a8cb6ef4aef69abc5c0f2d579648bd80d7733e1ccc3fbc90ed664a7f74006cb11bde87785f229ecd366c2d4e44432832580e0608c579e4cb76f383f7f551eac7471b00c36982",
	}

	b.ResetTimer()

	for _, hexInput := range testVectors {
		input, err := hex.DecodeString(hexInput)

		if err != nil {
			b.Errorf("hex decode failed")
		}

		for i := 0; i < b.N; i++ {
			_ = scrypt(input)
		}
	}
}
