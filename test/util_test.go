package tests

import (
	"test/utils"
	"testing"
)

func TestHelloWorld(t *testing.T) {
	expected := "hello world"
	result := utils.HelloWorld()

	if result != expected {
		t.Errorf("Expected %q, but got %q", expected, result)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	data := []byte("secret message")
	key := utils.GenRandByteSlice(32)

	encrypted := utils.Encrypt(data, key)
	decrypted := utils.Decrypt(encrypted, key)

	if string(decrypted) != string(data) {
		t.Errorf("Decryption failed. Expected %q, but got %q", string(data), string(decrypted))
	}
}

func TestCompressAndDecompress(t *testing.T) {
	data := []byte("compressed data")

	compressed := utils.Compress(data)
	decompressed := utils.Decompress(compressed)

	if string(decompressed) != string(data) {
		t.Errorf("Decompression failed. Expected %q, but got %q", string(data), string(decompressed))
	}
}

func TestEncodeAndDecode64(t *testing.T) {
	data := []byte("encoded data")

	encoded := utils.Encode64(data)
	decoded := utils.Decode64(encoded)

	if string(decoded) != string(data) {
		t.Errorf("Decoding failed. Expected %q, but got %q", string(data), string(decoded))
	}
}

func TestCheckArgon2Salt(t *testing.T) {
	password := []byte("password")
	salt := utils.GenRandByteSlice(16)
	passwordArgon2Salt := utils.ApplyArgon2Salt(password, salt)

	result := utils.CheckArgon2Salt(password, salt, passwordArgon2Salt)

	if !result {
		t.Errorf("Argon2 salt check failed. Expected true, but got false")
	}
}

func TestHash256(t *testing.T) {
	data := []byte("hash data")

	hash := utils.Hash256(data)

	if len(hash) != 32 {
		t.Errorf("Hashing failed. Expected hash length of 32, but got %d", len(hash))
	}
}

func TestHash512(t *testing.T) {
	data := []byte("hash data")

	hash := utils.Hash512(data)

	if len(hash) != 64 {
		t.Errorf("Hashing failed. Expected hash length of 64, but got %d", len(hash))
	}
}

func TestEncryptAesCtrAndDecryptAesCtr(t *testing.T) {
	data := []byte("secret message")
	key := utils.GenRandByteSlice(32)

	encrypted := utils.EncryptAesCtr(data, key)
	decrypted := utils.DecryptAesCtr(encrypted, key)

	if string(decrypted) != string(data) {
		t.Errorf("Decryption failed. Expected %q, but got %q", string(data), string(decrypted))
	}
}

func TestEncryptAesGcmAndDecryptAesGcm(t *testing.T) {
	data := []byte("secret message")
	key := utils.GenRandByteSlice(32)

	encrypted := utils.EncryptAesGcm(data, key)
	decrypted := utils.DecryptAesGcm(encrypted, key)

	if string(decrypted) != string(data) {
		t.Errorf("Decryption failed. Expected %q, but got %q", string(data), string(decrypted))
	}
}

func TestEncryptChaCha20AndDecryptChaCha20(t *testing.T) {
	data := []byte("secret message")
	key := utils.GenRandByteSlice(32)

	encrypted := utils.EncryptChaCha20(data, key)
	decrypted := utils.DecryptChaCha20(encrypted, key)

	if string(decrypted) != string(data) {
		t.Errorf("Decryption failed. Expected %q, but got %q", string(data), string(decrypted))
	}
}
