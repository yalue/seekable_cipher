package seekable_cipher

import (
	"bytes"
	"github.com/yalue/byte_utils"
	"io"
	"math/rand"
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

func TestMultiSeeks(t *testing.T) {
	rng := rand.New(rand.NewSource(1337))
	count := 200
	offsets := make([]int64, count)
	sizes := make([]int64, count)
	initialResults := make([][]byte, count)
	// The sizes will be between 0 and 2 MB
	maxSize := int64(2 * 1024 * 1024)
	for i := range sizes {
		sizes[i] = rng.Int63n(maxSize)
	}
	for i := range initialResults {
		initialResults[i] = make([]byte, sizes[i])
	}
	c := NewSeekableCipher("password1")
	var e error

	// Perform the first readings.
	for i := range offsets {
		_, e = c.Seek(offsets[i], io.SeekStart)
		if e != nil {
			t.Logf("Failed seeking to offset %d: %s\n", offsets[i], e)
			t.FailNow()
		}
		_, e = c.Read(initialResults[i])
		if e != nil {
			t.Logf("Failed reading at offset %d: %s\n", offsets[i], e)
			t.FailNow()
		}
	}

	// Verify that we get the same results on a second reading.
	buffer := make([]byte, maxSize)
	for i := range offsets {
		_, e = c.Seek(offsets[i], io.SeekStart)
		if e != nil {
			t.Logf("Failed seeking to offset %d: %s\n", offsets[i], e)
			t.FailNow()
		}
		_, e = c.Read(buffer[0:sizes[i]])
		if e != nil {
			t.Logf("Failed reading offset %d: %s\n", offsets[i], e)
			t.FailNow()
		}
		if !bytes.Equal(buffer[0:sizes[i]], initialResults[i]) {
			t.Logf("Bytes at offset %d didn't match the second time: "+
				"% x vs % x\n", offsets[i], buffer[0:16],
				initialResults[i][0:16])
			t.FailNow()
		}
	}
}

func TestCipherReadSeeker(t *testing.T) {
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

func TestCipherWriteSeeker(t *testing.T) {
	key := "This is the password! (but a bit different!)"
	originalData := []byte("Hi there!")
	dst := byte_utils.NewSeekableBuffer()
	w := NewCipherWriteSeeker(dst, key)
	bytesWritten, e := w.Write(originalData)
	if e != nil {
		t.Logf("Failed writing to seekable buffer: %s\n", e)
		t.FailNow()
	}
	if bytesWritten != len(originalData) {
		t.Logf("Wrote only %d/%d bytes of data\n", bytesWritten,
			len(originalData))
		t.FailNow()
	}
	t.Logf("Encrypted using writer % x -> % x\n", originalData, dst.Data)
	reconstructed := byte_utils.NewSeekableBuffer()
	otherWay := NewCipherWriteSeeker(reconstructed, key)
	_, e = otherWay.Write(dst.Data)
	if e != nil {
		t.Logf("Failed writing to seekable buffer (reconstructing): %s\n", e)
		t.FailNow()
	}
	if !bytes.Equal(reconstructed.Data, originalData) {
		t.Logf("Failed reconstructing original data using CipherWriteSeeker\n")
		t.FailNow()
	}
}
