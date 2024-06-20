package main

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	data := []byte("Hello, World!")
	key := GenRandByteSlice(32)

	encrypted := Encrypt(data, key)
	decrypted := Decrypt(encrypted, key)

	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decryption failed. Expected: %s, got: %s", data, decrypted)
	}
}

func TestCompressDecompress(t *testing.T) {
	data := []byte("Hello, World!")

	compressed := Compress(data)
	decompressed := Decompress(compressed)

	if !bytes.Equal(data, decompressed) {
		t.Errorf("Decompression failed. Expected: %s, got: %s", data, decompressed)
	}
}

func TestEncodeDecode64(t *testing.T) {
	data := []byte("Hello, World!")

	encoded := Encode64(data)
	decoded := Decode64(encoded)

	if !bytes.Equal(data, decoded) {
		t.Errorf("Decoding failed. Expected: %s, got: %s", data, decoded)
	}
}

func TestEncryptAesCtrDecryptAesCtr(t *testing.T) {
	data := []byte("Hello, World!")
	key := GenRandByteSlice(32)

	encrypted := EncryptAesCtr(data, key)
	decrypted := DecryptAesCtr(encrypted, key)

	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decryption failed. Expected: %s, got: %s", data, decrypted)
	}
}

func TestEncryptAesGcmDecryptAesGcm(t *testing.T) {
	data := []byte("Hello, World!")
	key := GenRandByteSlice(32)

	encrypted := EncryptAesGcm(data, key)
	decrypted := DecryptAesGcm(encrypted, key)

	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decryption failed. Expected: %s, got: %s", data, decrypted)
	}
}

func TestEncryptChaCha20DecryptChaCha20(t *testing.T) {
	data := []byte("Hello, World!")
	key := GenRandByteSlice(32)

	encrypted := EncryptChaCha20(data, key)
	decrypted := DecryptChaCha20(encrypted, key)

	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decryption failed. Expected: %s, got: %s", data, decrypted)
	}
}
