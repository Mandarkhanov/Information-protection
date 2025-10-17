package skipjack

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestEncryptDecryptSymmetry(t *testing.T) {
	key := make([]byte, 10)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "Empty File",
			plaintext: []byte{},
		},
		{
			name:      "Short Block (less than 8 bytes)",
			plaintext: []byte("hello"),
		},
		{
			name:      "Full Block (exactly 8 bytes)",
			plaintext: []byte("12345678"), // Критический тест для PKCS#7
		},
		{
			name:      "Multiple Blocks (not a multiple of 8)",
			plaintext: []byte("this is a longer test sentence"),
		},
		{
			name:      "Exact Multiple of Blocks (32 bytes)",
			plaintext: []byte("this is 32 bytes long sentence!"), // Еще один критический тест для PKCS#7
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// --- Фаза шифрования ---
			plaintextReader := bytes.NewReader(tc.plaintext)
			ciphertextBuffer := new(bytes.Buffer)

			_, err := EncryptFile(ciphertextBuffer, plaintextReader, key)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			if len(tc.plaintext) == 0 {
				if ciphertextBuffer.Len() != BlockSize {
					t.Fatalf("Expected ciphertext length for empty file to be %d, but got %d", BlockSize, ciphertextBuffer.Len())
				}
			} else if ciphertextBuffer.Len() == 0 {
				t.Fatal("Encryption produced empty ciphertext for non-empty plaintext")
			}

			// --- Фаза расшифровки ---
			ciphertextReader := bytes.NewReader(ciphertextBuffer.Bytes())
			decryptedBuffer := new(bytes.Buffer)

			_, err = DecryptFile(decryptedBuffer, ciphertextReader, key)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// --- Фаза проверки ---

			if !bytes.Equal(tc.plaintext, decryptedBuffer.Bytes()) {
				t.Errorf("Decrypted data does not match original plaintext")
				t.Logf("Original:  %x", tc.plaintext)
				t.Logf("Decrypted: %x", decryptedBuffer.Bytes())
			}
		})
	}
}

func TestInvalidKeySize(t *testing.T) {
	invalidKey := []byte{1, 2, 3}

	reader := new(bytes.Buffer)
	writer := io.Discard

	_, err := EncryptFile(writer, reader, invalidKey)
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("EncryptFile: expected error %v, but got %v", ErrInvalidKeySize, err)
	}

	_, err = DecryptFile(writer, reader, invalidKey)
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("DecryptFile: expected error %v, but got %v", ErrInvalidKeySize, err)
	}
}
