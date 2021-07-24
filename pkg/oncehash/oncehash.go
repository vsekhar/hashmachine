// package onceHash provides an interface for a hash that can only be used once.
//
// onceHash represents a common-denominator interface for both types of hash
// functions, those meeting hash.Hash and those meeting sha3.ShakeHash.
//
// The sha3 package resolves the differences between these interfaces by
// allocating on every call of Sum to copy the hash state.
//
// If instead the client program guarantees to call Sum only once and then not
// subsequently use the hash, we can treat a sha3.ShakeHash as a hash.Hash
// without the additional allocation.
//
// Note that we should enforce the Sum-and-discard contract for hash.Hash as
// well to ensure correctness doesn't depend on the happenstance of an
// execution not using sha3.ShakeHash. Hence we also wrap hash.Hash.
//
// The methods of onceHash and its implementation are not goroutine safe.
package oncehash

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

// Hash is a hash.Hash that can only be used once. Specifically, after
// calling Sum, calling any method other than Reset will panic.
type Hash interface {
	hash.Hash
}

type onceHashImpl struct {
	summed bool
}

// panics if summed (and not reset)
func (o onceHashImpl) ok() {
	if o.summed {
		panic("OnceHash: cannot be used after calling Sum, must be Reset")
	}
}

// shakeOnceWrapper makes a sha3.ShakeHash a OnceHash
type shakeOnceWrapper struct {
	onceHashImpl
	outputLength int
	h            sha3.ShakeHash
}

func (s *shakeOnceWrapper) Write(b []byte) (int, error) { s.ok(); return s.h.Write(b) }

func (s *shakeOnceWrapper) Sum(b []byte) []byte {
	s.ok()
	s.summed = true
	b = append(b, make([]byte, s.outputLength)...)
	s.h.Read(b[len(b)-s.outputLength:]) // never returns error
	return b
}

func (s *shakeOnceWrapper) Reset()    { s.summed = false; s.h.Reset() }
func (s *shakeOnceWrapper) Size() int { return s.outputLength }
func (s *shakeOnceWrapper) BlockSize() int {
	panic("oncehash: Shake hashes don't make available their block size / rate")
}

// WrapShake wraps a sha3.ShakeHash, fixes its outputLength and returns a
// OnceHash.
func WrapShake(s sha3.ShakeHash, outputLength int) Hash {
	return &shakeOnceWrapper{h: s, outputLength: outputLength}
}

// hashOnceWrapper makes a hash.Hash into a onceHash
type hashOnceWrapper struct {
	onceHashImpl
	h hash.Hash
}

func (h *hashOnceWrapper) Write(b []byte) (int, error) { h.ok(); return h.h.Write(b) }

func (h *hashOnceWrapper) Sum(b []byte) []byte {
	h.ok()
	h.summed = true
	return h.h.Sum(b)
}

func (h *hashOnceWrapper) Reset()         { h.summed = false; h.h.Reset() }
func (h *hashOnceWrapper) Size() int      { return h.h.Size() }
func (h *hashOnceWrapper) BlockSize() int { return h.h.BlockSize() }

// WrapHash wraps a hash.Hash and returns a OnceHash.
func WrapHash(h hash.Hash) Hash {
	return &hashOnceWrapper{h: h}
}
