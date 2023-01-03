package seekable_cipher

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

const (
	// The number of bits in a chunk's size. 20 = 1 MB chunks. Must be a
	// multiple of sha512.Size.
	chunkSizeBits = 20
	// The size, in bytes, of a single chunk of data.
	chunkSize = 1 << chunkSizeBits
	// Mask for the bits determining an offset into a single chunk
	chunkOffsetMask = chunkSize - 1
	chunkIndexMask  = ^uint64(chunkOffsetMask)
)

// Just offers a level of indirection around how we generate or get chunks of
// pseudorandom bytes.
type chunkCache interface {
	// Returns (possibly generating) a chunk of data at the given base offset.
	// Calling this may invalidate the data returned previously, if slice
	// memory is reused, so only call this when done with the previous chunk.
	getChunk(offset int64) []byte
}

// Implements the io.ReadSeeker interface.
type SeekableCipher struct {
	// The offset that Read(...) will read from next.
	currentOffset int64
	// The chunk of pseudorandom bytes we're currently reading from.
	currentChunk []byte
	// Basically wraps our underlying source of data.
	chunks chunkCache
}

// Implements the chunkCache interface. Create using newChunkCache. This
// "basic" version only caches the first chunk (index 0), under the assumption
// that a file's header is more important to cache. Additionally, it reuses
// memory for the remaining chunks.
type basicChunkCache struct {
	passphrase string
	firstChunk []byte
	buffer     []byte
}

// Fills the dst buffer (which must be chunkSize), given a Hash instance that
// has already been primed with the passphrase and offset.
func generateChunk(h hash.Hash, dst []byte) {
	hashSize := uint64(h.Size())
	currentHash := make([]byte, 0, hashSize)
	bytesGenerated := uint64(0)

	for bytesGenerated < chunkSize {
		currentHash = h.Sum(currentHash)
		copy(dst[bytesGenerated:bytesGenerated+hashSize], currentHash)
		h.Write(currentHash)
		bytesGenerated += hashSize
		// Note that Sum *appends* to the currentHash slice, so we'll just
		// reuse it by slicing it to 0 length.
		currentHash = currentHash[:0]
	}
}

func (c *basicChunkCache) getChunk(offset int64) []byte {
	h := sha512.New()
	alignedOffset := uint64(offset) & chunkIndexMask
	if alignedOffset == 0 {
		return c.firstChunk
	}

	// "Seed" the data generation by initializing the hash using the passphrase
	// and offset.
	h.Write([]byte(c.passphrase))
	var offsetBytes [8]byte
	binary.LittleEndian.PutUint64(offsetBytes[:], alignedOffset)
	h.Write(offsetBytes[:])
	generateChunk(h, c.buffer)
	return c.buffer
}

// A wrapper returning a chunkCache that generates chunks with the given
// passphrase.
func newChunkCache(passphrase string) chunkCache {
	toReturn := &basicChunkCache{
		passphrase: passphrase,
		firstChunk: make([]byte, chunkSize),
		buffer:     make([]byte, chunkSize),
	}
	// Pre-generate the first chunk, at offset 0.
	h := sha512.New()
	h.Write([]byte(passphrase))
	var offsetBytes [8]byte
	h.Write(offsetBytes[:])
	generateChunk(h, toReturn.firstChunk)
	return toReturn
}

// Returns a new SeekableCipher, initialized at offset 0, generating data using
// the given passphrase.
func NewSeekableCipher(passphrase string) *SeekableCipher {
	if (chunkSize % sha512.Size) != 0 {
		panic("Internal error: invalid chunk size for sha512-generated chunks")
	}
	chunks := newChunkCache(passphrase)
	return &SeekableCipher{
		currentOffset: 0,
		currentChunk:  chunks.getChunk(0),
		chunks:        chunks,
	}
}

func (c *SeekableCipher) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = c.currentOffset + offset
	case io.SeekEnd:
		return 0, fmt.Errorf("Can't seek relative to the end of the stream")
	default:
		return 0, fmt.Errorf("Invalid seek \"whence\": %d", whence)
	}
	if newOffset < 0 {
		return 0, fmt.Errorf("Invalid new offset: %d", newOffset)
	}
	c.currentChunk = c.chunks.getChunk(newOffset)
	c.currentOffset = newOffset
	return newOffset, nil
}

func (c *SeekableCipher) Read(data []byte) (int, error) {
	toRead := int64(len(data))
	bytesRead := int64(0)
	offsetInChunk := c.currentOffset & chunkOffsetMask
	remainingInChunk := chunkSize - offsetInChunk
	chunk := c.currentChunk
	for toRead > 0 {
		// Finish now if we're in the last chunk we need to read.
		if toRead <= remainingInChunk {
			copy(data[bytesRead:],
				chunk[offsetInChunk:offsetInChunk+toRead])
			c.currentOffset += toRead
			// Switch to the next chunk if we finished this one exactly.
			remainingInChunk -= toRead
			if remainingInChunk == 0 {
				c.currentChunk = c.chunks.getChunk(c.currentOffset)
			}
			return len(data), nil
		}

		// We'll need to use more than one chunk. Start by reading everything
		// remaining in this one.
		copy(data[bytesRead:], chunk[offsetInChunk:])
		bytesRead += remainingInChunk
		toRead -= remainingInChunk
		// Next, generate a new chunk.
		c.currentOffset += remainingInChunk
		c.currentChunk = c.chunks.getChunk(c.currentOffset)
		remainingInChunk = chunkSize
		offsetInChunk = 0
		chunk = c.currentChunk
	}
	return len(data), nil
}

// Sets dst to the xor of bytes in slices a and b, one byte at a time. Panics
// if b and dst aren't at least as long as a. It is valid for dst to be the
// same as either a or b.
func SimpleXor(dst, a, b []byte) {
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b[i]
	}
}

// Used to xor byte slices a and b, writing the result into dst. Based on
// github.com/golang/go/issues/31586#issuecomment-487436401. Panics b and dst
// aren't at least as long as a. It's valid for dst to be the same as either a
// or b. Benchmarks on my machine (tm) indicate that this is over 3x faster
// than SimpleXor alone for 1 MB slices, though this may change depending on
// architecture.
func FastXor(dst, a, b []byte) {
	n := binary.LittleEndian
	var x, y uint64
	for len(a) >= 32 {
		x = n.Uint64(a)
		y = n.Uint64(b)
		n.PutUint64(dst, x^y)
		x = n.Uint64(a[8:])
		y = n.Uint64(b[8:])
		n.PutUint64(dst[8:], x^y)
		x = n.Uint64(a[16:])
		y = n.Uint64(b[16:])
		n.PutUint64(dst[16:], x^y)
		x = n.Uint64(a[24:])
		y = n.Uint64(b[24:])
		n.PutUint64(dst[24:], x^y)
		a = a[32:]
		b = b[32:]
		dst = dst[32:]
	}
	SimpleXor(dst, a, b)
}

// Wraps an io.ReadSeeker where Read operations Xor data from a seekable cipher
// with data obtained from an underlying io.ReadSeeker.
type CipherReadSeeker struct {
	data         io.ReadSeeker
	cipherStream io.ReadSeeker
	// Used to avoid reallocating stuff every time we xor data.
	cipherBytesBuffer []byte
}

// Returns a new CipherReadSeeker, pulling encrypted data from the given
// underlying ReadSeeker and decrypting the data returned via Read using the
// seekable cipher with the given key.
func NewCipherReadSeeker(underlying io.ReadSeeker,
	key string) *CipherReadSeeker {
	return &CipherReadSeeker{
		data:              underlying,
		cipherStream:      NewSeekableCipher(key),
		cipherBytesBuffer: make([]byte, 10*1024*1024),
	}
}

func (r *CipherReadSeeker) Seek(offset int64, whence int) (int64, error) {
	newOffset, e := r.data.Seek(offset, whence)
	if e != nil {
		return newOffset, fmt.Errorf("Error seeking in underlying data: %w", e)
	}
	newOffset2, e := r.cipherStream.Seek(offset, whence)
	if e != nil {
		return newOffset, fmt.Errorf("Error seeking in cipher stream: %w", e)
	}
	if newOffset != newOffset2 {
		return 0, fmt.Errorf("Internal error: offset in cipher not equal to "+
			"offset in encrypted data (%d vs %d)", newOffset2, newOffset)
	}
	return newOffset, nil
}

func (r *CipherReadSeeker) Read(dst []byte) (int, error) {
	amountRead, e := r.data.Read(dst)
	isEOF := false
	if (e != nil) && !errors.Is(e, io.EOF) {
		return 0, fmt.Errorf("Error reading underlying data: %w", e)
	}
	if e != nil && errors.Is(e, io.EOF) {
		// We'll ignore EOF errors for now here, since we'll need to XOR the
		// returned stuff even if it hit EOF.
		isEOF = true
	}

	// We do this in a loop, in order to avoid reallocating the buffer of
	// the cipher bytes, which may be too small to cover all of dst at once.
	bytesXORed := 0
	b := r.cipherBytesBuffer
	for bytesXORed < amountRead {
		amountToXOR := amountRead - bytesXORed
		if amountToXOR > len(b) {
			amountToXOR = len(b)
		}
		// Unless our underlying implementation changes, it should remain safe
		// to omit error checking for this Read(...).
		r.cipherStream.Read(b[:amountToXOR])
		dstEndOffset := bytesXORed + amountToXOR
		FastXor(dst[bytesXORed:dstEndOffset], dst[bytesXORed:dstEndOffset],
			b[:amountToXOR])
		bytesXORed += amountToXOR
	}
	if isEOF {
		return amountRead, io.EOF
	}
	return amountRead, nil
}

// Wraps an io.WriteSeeker where Write operations Xor data from a seekable
// cipher before writing data to an underlying io.WriteSeeker.
type CipherWriteSeeker struct {
	dst          io.WriteSeeker
	cipherStream io.ReadSeeker
	// Used to avoid reallocating stuff every time we xor data.
	cipherBytesBuffer []byte
}

func NewCipherWriteSeeker(sink io.WriteSeeker, key string) *CipherWriteSeeker {
	return &CipherWriteSeeker{
		dst:               sink,
		cipherStream:      NewSeekableCipher(key),
		cipherBytesBuffer: make([]byte, 10*1024*1024),
	}
}

func (w *CipherWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	newOffset, e := w.dst.Seek(offset, whence)
	if e != nil {
		return newOffset, fmt.Errorf("Error seeking in underlying dst: %w", e)
	}
	newOffset2, e := w.cipherStream.Seek(offset, whence)
	if e != nil {
		return newOffset, fmt.Errorf("Error seeking in cipher stream: %w", e)
	}
	if newOffset != newOffset2 {
		return 0, fmt.Errorf("Internal error: offset in cipher not equal to "+
			"offset in encrypted data sink (%d vs %d)", newOffset2, newOffset)
	}
	return newOffset, nil
}

// In the case of a write failure, this attempts to reset the offset in the
// cipher stream to match the offset in the output sink. Returns an error if
// one occurs.
func (w *CipherWriteSeeker) resetCipherOffset() error {
	offset, e := w.dst.Seek(0, io.SeekCurrent)
	if e != nil {
		return fmt.Errorf("Failed getting current offset in data sink: %w", e)
	}
	_, e = w.cipherStream.Seek(offset, io.SeekStart)
	return e
}

func (w *CipherWriteSeeker) Write(data []byte) (int, error) {
	bytesWritten := 0
	b := w.cipherBytesBuffer
	for bytesWritten < len(data) {
		toWrite := len(data) - bytesWritten
		if toWrite > len(b) {
			toWrite = len(b)
		}
		// See note in CipherReadSeeker.Read
		w.cipherStream.Read(b[:toWrite])
		// We'll overwrite the temporary buffer with the XOR result
		FastXor(b[:toWrite], b[:toWrite], data[bytesWritten:])
		tmp, e := w.dst.Write(b[:toWrite])
		if e != nil {
			// We'll attempt to recover this error by reverting the cipher's
			// offset to match the sink's offset, in case the write gets
			// retried.
			w.resetCipherOffset()
			return bytesWritten + tmp,
				fmt.Errorf("Error writing to underlying sink: %w", e)
		}
		bytesWritten += toWrite
	}
	return bytesWritten, nil
}
