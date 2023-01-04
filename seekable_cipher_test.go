package seekable_cipher

import (
	"bytes"
	"io"
	"testing"
)

func TestSeekableCipher(t *testing.T) {
	first16Bytes := []byte{0x39, 0xeb, 0xfb, 0x43, 0x8d, 0xba, 0x85, 0xd5,
		0x61, 0xde, 0xc0, 0xba, 0x6c, 0xd9, 0x24, 0xcf}
	c := NewSeekableCipher("a")
	bytesA := make([]byte, 2*1024*1024)
	size, e := c.Read(bytesA)
	if e != nil {
		t.Logf("Failed reading at offset 0: %s\n", e)
		t.FailNow()
	}
	if size != len(bytesA) {
		t.Logf("Failed reading full amount, got %d bytes, expected %d\n",
			size, len(bytesA))
		t.FailNow()
	}
	t.Logf("Source a: First 16 bytes: % x\n", bytesA[0:16])
	if !bytes.Equal(bytesA[0:16], first16Bytes) {
		t.Logf("Incorrect first 16 bytes. Expected % x, got % x\n",
			first16Bytes, bytesA[0:16])
		t.FailNow()
	}
	_, e = c.Seek(0, io.SeekStart)
	if e != nil {
		t.Logf("Failed seeking to beginning: %s\n", e)
		t.FailNow()
	}
	_, e = c.Read(bytesA)
	if e != nil {
		t.Logf("Read after returning to start failed: %s\n", e)
		t.FailNow()
	}
	if !bytes.Equal(bytesA[0:16], first16Bytes) {
		t.Logf("Incorrect bytes after returning to start. Expected % x, "+
			"got % x\n", first16Bytes, bytesA[0:16])
		t.FailNow()
	}

	d := NewSeekableCipher("b")
	bytesB := make([]byte, 16)
	_, e = d.Read(bytesB)
	t.Logf("Source b: First 16 bytes: % x\n", bytesB[0:16])
	if bytes.Equal(bytesA[0:16], bytesB) {
		t.Logf("Different keys produced the same bytes!")
		t.FailNow()
	}
	// Make sure the start
	newOffset := int64(1024*1024) + 1337
	a := make([]byte, 16)
	copy(a, bytesA[newOffset:newOffset+16])
	tmp, e := c.Seek(newOffset, io.SeekStart)
	if e != nil {
		t.Logf("Failed seeking to offset %d: %s\n", newOffset, e)
		t.FailNow()
	}
	if tmp != newOffset {
		t.Logf("Seek returned incorrect offset: expected %d, got %d\n",
			newOffset, tmp)
		t.FailNow()
	}
	_, e = c.Read(bytesA[0:16])
	if e != nil {
		t.Logf("Failed reading after seek: %s\n", e)
		t.FailNow()
	}
	if !bytes.Equal(bytesA[0:16], a) {
		t.Logf("Didn't get same contents after seeking: % x vs % x\n",
			bytesA[0:16], a)
		t.FailNow()
	}
}

func TestDecryptReadSeeker(t *testing.T) {
	key := "This is the password!"
	originalData := []byte("Hi there!")
	r := NewCipherReadSeeker(bytes.NewReader(originalData), key)
	encrypted, e := io.ReadAll(r)
	if e != nil {
		t.Logf("Error reading full ciphertext: %s\n", e)
		t.FailNow()
	}
	t.Logf("Original data: % x, encrypted: % x\n", originalData, encrypted)
	if bytes.Equal(originalData, encrypted) {
		t.Logf("Encryption didn't change the original data.\n")
		t.FailNow()
	}
	r2 := NewCipherReadSeeker(bytes.NewReader(encrypted), key)
	decrypted, e := io.ReadAll(r2)
	if e != nil {
		t.Logf("Error reading reconstructed text: %s\n", e)
		t.FailNow()
	}
	if !bytes.Equal(originalData, decrypted) {
		t.Logf("Failed reconstructing original text.\n")
		t.FailNow()
	}
}

// TODO (next): Write a test for SeekableWriteSeeker
