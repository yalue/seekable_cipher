package seekable_cipher

import (
	"crypto/sha512"
	"encoding/binary"
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
// "basic" version doesn't actually cache anything, apart from reusing a single
// buffer in order to avoid allocating new memory for chunks every time.
type basicChunkCache struct {
	passphrase string
	buffer []byte
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
	return &basicChunkCache{
		passphrase: passphrase,
		buffer: make([]byte, chunkSize),
	}
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
