package skipjack

import (
	"math/bits"
	"testing"
)

func TestAvalancheEffect(t *testing.T) {
	originalMessage := []byte("Cryptography is the practice and study of techniques for secure communication.")
	originalHash := Hash(originalMessage)

	modifiedMessage := make([]byte, len(originalMessage))
	copy(modifiedMessage, originalMessage)
	modifiedMessage[0] ^= 0x01
	modifiedHash := Hash(modifiedMessage)

	if originalHash == modifiedHash {
		t.Fatalf("Avalanche effect failed: hashes for original and modified messages are identical.\nOriginal hash: %x\nModified hash: %x", originalHash, modifiedHash)
	}

	diffBits := 0
	for i := 0; i < BlockSize; i++ {
		xorByte := originalHash[i] ^ modifiedHash[i]
		diffBits += bits.OnesCount8(xorByte)
	}

	totalBits := BlockSize * 8
	// 6. Проверяем, что изменилась значительная часть бит.
	// Хорошим показателем является изменение >25% бит. Для 64-битного хеша это >16 бит.
	// Установим порог в 20 для надежности.
	threshold := totalBits / 3 // Ожидаем, что изменится хотя бы треть бит

	t.Logf("Avalanche test results: %d out of %d bits changed (%.2f%%)",
		diffBits, totalBits, (float64(diffBits)/float64(totalBits))*100)

	if diffBits < threshold {
		t.Errorf("Avalanche effect is weak: only %d bits changed, which is less than the threshold of %d", diffBits, threshold)
	}
}
