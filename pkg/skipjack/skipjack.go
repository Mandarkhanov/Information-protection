package skipjack

import (
	"bytes"
	"errors"
	"io"
)

const BlockSize = 8

var (
	ErrInvalidKeySize   = errors.New("invalid key size: key must be 10 bytes")
	ErrInvalidBlockSize = errors.New("invalid block size: input data must be a multiple of 8 bytes")
	ErrInvalidPadding   = errors.New("invalid padding: cannot remove PKCS#7 padding")
)

type Words struct {
	w1 [2]byte
	w2 [2]byte
	w3 [2]byte
	w4 [2]byte
}

func NewWords(P [8]byte) Words {
	return Words{
		w1: [2]byte(P[:2]),
		w2: [2]byte(P[2:4]),
		w3: [2]byte(P[4:6]),
		w4: [2]byte(P[6:]),
	}
}

func (w *Words) JoinWords() (bytes [8]byte) {
	copy(bytes[:2], w.w1[:])
	copy(bytes[2:4], w.w2[:])
	copy(bytes[4:6], w.w3[:])
	copy(bytes[6:], w.w4[:])
	return bytes
}

func EncryptFile(writer io.Writer, reader io.Reader, key []byte) (int64, error) {
	if len(key) != 10 {
		return 0, ErrInvalidKeySize
	}

	cw := &cipherWriter{
		w:     writer,
		key:   [10]byte(key),
		block: make([]byte, 0, BlockSize),
	}

	written, err := io.Copy(cw, reader)
	if err != nil {
		return written, err
	}

	if err := cw.Close(); err != nil {
		return written, err
	}

	return written, nil
}

type cipherWriter struct {
	w      io.Writer
	key    [10]byte
	block  []byte
	closed bool
}

// Write накапливает данные в блок и шифрует, когда блок полон.
func (cw *cipherWriter) Write(p []byte) (n int, err error) {
	if cw.closed {
		return 0, errors.New("write to closed cipherWriter")
	}

	totalWritten := 0
	for len(p) > 0 {
		needed := BlockSize - len(cw.block)
		if needed == 0 { // Блок уже полон, шифруем его
			encrypted := Encrypt([BlockSize]byte(cw.block), cw.key)
			if _, err := cw.w.Write(encrypted[:]); err != nil {
				return totalWritten, err
			}
			cw.block = cw.block[:0]
			continue
		}

		toCopy := needed
		if len(p) < needed {
			toCopy = len(p)
		}

		cw.block = append(cw.block, p[:toCopy]...)
		p = p[toCopy:]
		totalWritten += toCopy
	}
	return totalWritten, nil
}

// Close обрабатывает последний блок и добавляет паддинг.
func (cw *cipherWriter) Close() error {
	if cw.closed {
		return nil
	}
	cw.closed = true

	paddedBlock := addPKCS7Padding(cw.block)
	encrypted := Encrypt(paddedBlock, cw.key)
	_, err := cw.w.Write(encrypted[:])
	return err
}

func DecryptFile(writer io.Writer, reader io.Reader, key []byte) (int64, error) {
	if len(key) != 10 {
		return 0, ErrInvalidKeySize
	}
	key10 := [10]byte(key)

	var prevBlock, currentBlock [BlockSize]byte
	var written int64 = 0

	// Читаем первый блок.
	n, err := io.ReadFull(reader, prevBlock[:])
	if err == io.EOF || n == 0 {
		return 0, nil
	}
	if err != nil && err != io.ErrUnexpectedEOF {
		return 0, err
	}

	// Если файл меньше одного блока, это ошибка шифротекста.
	if n < BlockSize {
		return 0, ErrInvalidBlockSize
	}

	for {
		n, err = io.ReadFull(reader, currentBlock[:])

		// Если мы успешно прочитали следующий блок, значит, предыдущий не был последним.
		// Расшифровываем предыдущий блок и записываем.
		if n == BlockSize {
			decryptedBlock := Decrypt(prevBlock, key10)
			nw, writeErr := writer.Write(decryptedBlock[:])
			if writeErr != nil {
				return written, writeErr
			}
			written += int64(nw)
			prevBlock = currentBlock
		} else if err == io.EOF || err == io.ErrUnexpectedEOF { // Достигли конца файла.
			// prevBlock - это последний блок. Расшифровываем его.
			lastDecryptedBlock := Decrypt(prevBlock, key10)

			// Удаляем padding.
			unpaddedData, removeErr := removePKCS7Padding(lastDecryptedBlock)
			if removeErr != nil {
				return written, removeErr
			}

			// Записываем данные без дополнения.
			if len(unpaddedData) > 0 {
				nw, writeErr := writer.Write(unpaddedData)
				if writeErr != nil {
					return written, writeErr
				}
				written += int64(nw)
			}

			// Завершаем работу.
			break
		} else { // Любая другая ошибка чтения.
			return written, err
		}
	}

	return written, nil
}

func addPKCS7Padding(data []byte) [BlockSize]byte {
	padSize := BlockSize - len(data)
	padding := bytes.Repeat([]byte{byte(padSize)}, padSize)
	paddedData := append(data, padding...)
	var block [BlockSize]byte
	copy(block[:], paddedData)
	return block
}

func removePKCS7Padding(data [BlockSize]byte) ([]byte, error) {
	dataLen := len(data)
	if dataLen == 0 {
		return nil, ErrInvalidPadding
	}

	padSize := int(data[dataLen-1])
	if padSize > BlockSize || padSize == 0 {
		return nil, ErrInvalidPadding
	}

	padding := data[dataLen-padSize:]
	for _, b := range padding {
		if int(b) != padSize {
			return nil, ErrInvalidPadding
		}
	}

	return data[:dataLen-padSize], nil
}

func Encrypt(block [BlockSize]byte, key [10]byte) [BlockSize]byte {
	words := NewWords(block)

	res1 := run8rounds(ruleA, words, key, 1)
	res2 := run8rounds(ruleB, res1, key, 9)
	res3 := run8rounds(ruleA, res2, key, 17)
	res4 := run8rounds(ruleB, res3, key, 25)

	return res4.JoinWords()
}

func Decrypt(block [BlockSize]byte, key [10]byte) [BlockSize]byte {
	words := NewWords(block)

	res1 := run8rounds(inverseRuleB, words, key, 32)
	res2 := run8rounds(inverseRuleA, res1, key, 24)
	res3 := run8rounds(inverseRuleB, res2, key, 16)
	res4 := run8rounds(inverseRuleA, res3, key, 8)

	return res4.JoinWords()
}

func run8rounds(r rule, in Words, key [10]byte, startRound int) Words {
	out := in
	// Проверяем, это шифрование или расшифровка
	if startRound%8 != 0 { // Шифрование: 1->8, 9->16, 17->24, 25->32
		for i := 0; i < 8; i++ {
			roundNumber := startRound + i
			key4byte := getKeyForRound(key, roundNumber)
			out = r(out, key4byte, [2]byte{0, byte(roundNumber)})
		}
	} else { // Расшифровка: 32->25, 24->17, 16->9, 8->1
		for i := 0; i < 8; i++ {
			roundNumber := startRound - i
			key4byte := getKeyForRound(key, roundNumber)
			out = r(out, key4byte, [2]byte{0, byte(roundNumber)})
		}
	}
	return out
}

func getKeyForRound(key [10]byte, roundNumber int) [4]byte {
	idx := 4 * (roundNumber - 1)
	return [4]byte{
		key[idx%10],
		key[(idx+1)%10],
		key[(idx+2)%10],
		key[(idx+3)%10],
	}
}

type rule = func(Words, [4]byte, [2]byte) Words

func ruleA(in Words, key [4]byte, i [2]byte) Words {
	gResult := g(in.w1, key)
	return Words{
		w1: xor3Words(gResult, in.w4, i),
		w2: gResult,
		w3: in.w2,
		w4: in.w3,
	}
}

func ruleB(in Words, key [4]byte, i [2]byte) Words {
	return Words{
		w1: in.w4,
		w2: g(in.w1, key),
		w3: xor3Words(in.w1, in.w2, i),
		w4: in.w3,
	}
}

func inverseRuleA(out Words, key [4]byte, i [2]byte) Words {
	gResult := out.w2
	return Words{
		w1: g_inverse(gResult, key),
		w2: out.w3,
		w3: out.w4,
		w4: xor3Words(gResult, out.w1, i),
	}
}

func inverseRuleB(out Words, key [4]byte, i [2]byte) Words {
	w1_old := g_inverse(out.w2, key)
	return Words{
		w1: w1_old,
		w2: xor3Words(w1_old, out.w3, i),
		w3: out.w4,
		w4: out.w1,
	}
}

func xor3Words(a, b, c [2]byte) [2]byte {
	return [2]byte{a[0] ^ b[0] ^ c[0], a[1] ^ b[1] ^ c[1]}
}

func g(in [2]byte, k [4]byte) (out [2]byte) {
	L, R := in[0], in[1]

	L = L ^ f(R^k[0])
	R = R ^ f(L^k[1])
	L = L ^ f(R^k[2])
	R = R ^ f(L^k[3])

	return [2]byte{L, R}
}

func g_inverse(in [2]byte, k [4]byte) (out [2]byte) {
	L, R := in[0], in[1]
	R = R ^ f(L^k[3])
	L = L ^ f(R^k[2])
	R = R ^ f(L^k[1])
	L = L ^ f(R^k[0])
	return [2]byte{L, R}
}

var fTable = [256]byte{
	0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
	0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
	0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
	0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
	0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
	0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
	0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
	0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
	0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
	0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
	0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
	0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
	0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
	0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
	0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
	0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
}

func f(idx byte) byte {
	return fTable[idx]
}
