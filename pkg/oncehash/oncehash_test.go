package oncehash_test

import (
	"crypto/sha256"
	"testing"

	"github.com/vsekhar/hashmachine/pkg/oncehash"
	"golang.org/x/crypto/sha3"
)

func expectPanic(t *testing.T, prefix string, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("%s: expected panic did not occur", prefix)
		}
	}()
	f()
}

func writeSomething(t *testing.T, h oncehash.Hash) {
	if _, err := h.Write([]byte("abc")); err != nil {
		t.Error(err)
	}
}

func makeHashers() map[string]oncehash.Hash {
	r := make(map[string]oncehash.Hash)
	r["hash"] = oncehash.WrapHash(sha256.New())
	r["shakehash"] = oncehash.WrapShake(sha3.NewShake128(), 64)
	return r
}

func TestOnceHash(t *testing.T) {
	hs := makeHashers()
	for n, h := range hs {
		writeSomething(t, h)
		h.Sum(nil)

		// Write and Sum should panic after Sum
		expectPanic(t, n+": write-after-sum", func() {
			writeSomething(t, h)
		})
		expectPanic(t, n+": sum-after-sum", func() {
			h.Sum(nil)
		})

		// Write and Sum should work after reset
		h.Reset()
		writeSomething(t, h)
		h.Sum(nil)
	}
}

func TestSize(t *testing.T) {
	hs := makeHashers()
	if hs["hash"].BlockSize() != 64 {
		t.Errorf("expected blocksize 64, got %d", hs["hash"].BlockSize())
	}
	expectPanic(t, "shakehash block size", func() {
		hs["shakehash"].BlockSize()
	})
}
