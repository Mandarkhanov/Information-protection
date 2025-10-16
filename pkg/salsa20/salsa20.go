package salsa20

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

const (
	const1 uint32 = 0x61707865
	const2 uint32 = 0x3320646e
	const3 uint32 = 0x79622d32
	const4 uint32 = 0x6b206574
)

func initState(key [8]uint32, nonce, idx uint64) (state [16]uint32) {
	state = [16]uint32{
		const1, key[0], key[1], key[2],

		key[3], const2, uint32(nonce), uint32(nonce >> 32),

		uint32(idx), uint32(idx >> 32), const3, key[4],

		key[5], key[6], key[7], const4,
	}
	return state
}

func Encrypt(plainBytes []byte, key []byte) ([]byte, error) {
	k, err := checkAndConvertKey(key)
	if err != nil {
		return nil, err
	}

	originalLen := uint64(len(plainBytes))

	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := binary.LittleEndian.Uint64(nonceBytes)

	plainedBlocks, err := splitByBlocks(plainBytes)
	if err != nil {
		return nil, err
	}

	encryptedBytes := make([]byte, 0, len(plainBytes))
	var blockIdx uint64
	for _, b := range plainedBlocks {
		encryptedBlock := encodeBlock(b, k, nonce, blockIdx)
		blockIdx++
		encryptedBytes = append(encryptedBytes, joinBlocksToBytes(encryptedBlock)...)
	}

	// Финальный пакет: Nonce + Длина + Шифротекст
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, originalLen)

	result := append(nonceBytes, lenBytes...)
	result = append(result, encryptedBytes...)

	return result, nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Минимальная длина: 8 (nonce) + 8 (length)
	if len(ciphertext) < 16 {
		return nil, errors.New("invalid ciphertext: too short")
	}

	k, err := checkAndConvertKey(key)
	if err != nil {
		return nil, err
	}

	nonceBytes := ciphertext[0:8]
	lenBytes := ciphertext[8:16]
	data := ciphertext[16:]

	nonce := binary.LittleEndian.Uint64(nonceBytes)
	originalLen := binary.LittleEndian.Uint64(lenBytes)

	if len(data)%blockSize != 0 {
		return nil, errors.New("invalid ciphertext: data length is not a multiple of block size")
	}

	cryptedBlocks, err := splitByBlocks(data)
	if err != nil {
		return nil, err
	}

	decryptedBytes := make([]byte, 0, len(data))
	var blockIdx uint64
	for _, b := range cryptedBlocks {
		decryptedBlock := encodeBlock(b, k, nonce, blockIdx)
		blockIdx++
		decryptedBytes = append(decryptedBytes, joinBlocksToBytes(decryptedBlock)...)
	}

	// расшифрованный текст до исходной длины
	if uint64(len(decryptedBytes)) < originalLen {
		return nil, errors.New("invalid ciphertext: data is shorter than declared original length")
	}

	return decryptedBytes[:originalLen], nil
}

func encodeBlock(plainBlock [16]uint32, key [8]uint32, nonce, blockIdx uint64) (encryptedBlock [16]uint32) {
	initialState := initState(key, nonce, blockIdx)
	mixedState := getMixedState(initialState)
	keystreamBlock := getKeystreamBlock(mixedState, initialState)
	encryptedBlock = xorBlocks(plainBlock, keystreamBlock)
	return encryptedBlock
}

func xorBlocks(a, b [16]uint32) [16]uint32 {
	c := [16]uint32{}
	for i := range 16 {
		c[i] = a[i] ^ b[i]
	}
	return c
}

const blockSize = 64

func splitByBlocks(data []byte) ([][16]uint32, error) {
	numBlocks := (len(data) + blockSize - 1) / blockSize
	result := make([][16]uint32, numBlocks)

	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[start:end] // need to convert to [16]uint32
		block, err := convertBytesTo16Uint32(chunk)
		if err != nil {
			return result, err
		}
		result[i] = block
	}

	return result, nil
}

func convertBytesTo16Uint32(src []byte) ([16]uint32, error) {
	if len(src) > 64 {
		return [16]uint32{}, fmt.Errorf("source must be 64 bytes, got %d", len(src))
	}

	result := [16]uint32{}
	for j := 0; j < 16; j++ {
		start := j * 4
		end := start + 4

		if end <= len(src) {
			result[j] = binary.LittleEndian.Uint32(src[start:end])
		} else if start < len(src) {
			tmpWord := make([]byte, 4)
			copy(tmpWord, src[start:])
			result[j] = binary.LittleEndian.Uint32(tmpWord[:])
		} else {
			break
		}
	}

	return result, nil
}

func joinBlocksToBytes(blocks [16]uint32) []byte {
	result := make([]byte, 64)
	for i, v := range blocks {
		start := i * 4
		binary.LittleEndian.PutUint32(result[start:start+4], v)
	}
	return result
}

func getKeystreamBlock(mixedState [16]uint32, srcState [16]uint32) [16]uint32 {
	keystreamBlock := [16]uint32{}
	for i := range 16 {
		keystreamBlock[i] = mixedState[i] + srcState[i]
	}
	return keystreamBlock
}

func checkAndConvertKey(key []byte) ([8]uint32, error) {
	var key32 [8]uint32
	var finalKeyBytes []byte

	switch len(key) {
	case 32:
		finalKeyBytes = key
	case 16:
		finalKeyBytes = append(key, key...)
	default:
		return [8]uint32{}, errors.New("invalid key format: key must be 32 or 16 bytes")
	}

	for i := 0; i < 8; i++ {
		key32[i] = binary.LittleEndian.Uint32(finalKeyBytes[i*4 : (i+1)*4])
	}
	return key32, nil
}

func getMixedState(state [16]uint32) (mixedState [16]uint32) {
	tmpState := state
	for range 10 {
		columnRound(&tmpState)
		rowRound(&tmpState)
	}
	return tmpState
}

func quarterRound(a, b, c, d *uint32) {
	*b = *b ^ (bits.RotateLeft32((*a + *d), 7))
	*c = *c ^ (bits.RotateLeft32((*b + *a), 9))
	*d = *d ^ (bits.RotateLeft32((*c + *b), 13))
	*a = *a ^ (bits.RotateLeft32((*d + *c), 18))
}

func columnRound(x *[16]uint32) {
	quarterRound(&x[0], &x[4], &x[8], &x[12])  // 1-й столбец
	quarterRound(&x[5], &x[9], &x[13], &x[1])  // 2-й столбец
	quarterRound(&x[10], &x[14], &x[2], &x[6]) // 3-й столбец
	quarterRound(&x[15], &x[3], &x[7], &x[11]) // 4-й столбец
}

func rowRound(x *[16]uint32) {
	quarterRound(&x[0], &x[1], &x[2], &x[3])     // 1-я строка
	quarterRound(&x[5], &x[6], &x[7], &x[4])     // 2-я строка
	quarterRound(&x[10], &x[11], &x[8], &x[9])   // 3-я строка
	quarterRound(&x[15], &x[12], &x[13], &x[14]) // 4-я строка
}

func PrintMatrix(m [16]uint32) {
	fmt.Println("Salsa20 Matrix:")
	for i := range 4 {
		fmt.Print("|")
		for j := range 4 {
			fmt.Printf("0x%08x", m[i*4+j])
			if j != 3 {
				fmt.Print(" ")
			} else {
				fmt.Print("|\n")
			}
		}
	}
}
