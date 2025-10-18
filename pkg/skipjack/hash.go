package skipjack

import "encoding/binary"

var IV = [BlockSize]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

func Hash(message []byte) [BlockSize]byte {
	paddedMessage := addMerkleDamgårdPadding(message)

	hashState := IV
	for i := 0; i < len(paddedMessage); i += BlockSize {
		block := [BlockSize]byte{}
		copy(block[:], paddedMessage[i:i+BlockSize])

		key := [10]byte{}
		copy(key[:], block[:])

		encryptedState := Encrypt(hashState, key)

		for j := 0; j < BlockSize; j++ {
			hashState[j] = hashState[j] ^ encryptedState[j]
		}
	}

	return hashState
}

func addMerkleDamgårdPadding(message []byte) []byte {
	originLen := len(message)

	padded := append(message, 0x80) // add '1'

	bytesToPad := (BlockSize - (len(padded) % BlockSize) + BlockSize) % BlockSize
	padded = append(padded, make([]byte, bytesToPad)...) // add '...000'

	lenBytes := make([]byte, BlockSize)
	binary.BigEndian.PutUint64(lenBytes, uint64(originLen*8))
	return append(padded, lenBytes...)
}
