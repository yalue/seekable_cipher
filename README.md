Seekable Cipher
===============

A quick wrapper using SHA-512 to provide a seekable source of pseudo-random
bytes.  Uses sha512 as a PRNG.

Not intended for serious security applications, just written for my own
entertainment.

Usage
-----

```go
import "github.com/yalue/seekable_cipher"

func main() {
    // The value returned by NewSeekableCipher implements io.ReadSeeker
    s := seekable_cipher.NewSeekableCipher("my_passphrase")
}

```

