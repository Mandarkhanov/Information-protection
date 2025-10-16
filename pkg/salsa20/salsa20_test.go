package salsa20

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	// --- 1. Подготовка данных ---

	key := []byte("a very secret 32-byte key yeah!!")
	originalText := []byte("Это тестовое сообщение для проверки корректности работы алгоритма Salsa20.")

	// --- 2. Шифрование ---

	ciphertext, err := Encrypt(originalText, key)
	if err != nil {
		t.Fatalf("Encrypt() failed unexpectedly: %v", err)
	}

	// --- 3. Расшифровка ---

	decryptedText, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt() failed unexpectedly: %v", err)
	}

	// --- 4. Проверка результата ---

	if !bytes.Equal(decryptedText, originalText) {
		t.Errorf("FAIL: original and decrypted text do not match\nOriginal:  %q\nDecrypted: %q", originalText, decryptedText)
	}
}

func TestEncrypt_InvalidKey(t *testing.T) {
	key := []byte("short key")
	text := []byte("some text")

	_, err := Encrypt(text, key)
	if err == nil {
		t.Fatal("Expected an error for invalid key length, but got nil")
	}
}
