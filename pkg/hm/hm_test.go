package hm_test

import (
	"encoding/base64"
	"testing"

	"github.com/vsekhar/hashmachine"
	"github.com/vsekhar/hashmachine/pkg/hm"
)

func DecodeBase64OrDie(s string) []byte {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func Encode(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

var hashInput *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 1,
		BranchingFactor:    0,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH, Index: 1},
	},
}

var hashInput2 *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 2,
		BranchingFactor:    0,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH, Index: 2},
	},
}

var hashInput3 *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 3,
		BranchingFactor:    0,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 2},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH, Index: 3},
	},
}

// The tests below use the following MMR, where leafs are just the
// corresponding letter and non-leafs are the hashes of their children.
//
//         ---- o ----
//       /             \
//       g              n
//      /  \           /  \
//    /     \         /    \
//    c      f       j     m      r
//   / \    / \     / \   / \    /  \
//   a  b  d   e   h   i k   l   p  q   s

var (
	// Leaves
	a = []byte("a")
	b = []byte("b")
	d = []byte("d")
	e = []byte("e")
	h = []byte("h")
	i = []byte("i")
	k = []byte("k")
	l = []byte("l")
	p = []byte("p")
	q = []byte("q")
	s = []byte("s")

	// Second level
	c = DecodeBase64OrDie("+44g/C5MPySMYMOb1lLzwTRymLuXe4tNWQO4UFViBgM")
	f = DecodeBase64OrDie("lZpF1E5vz1g2HtAEaBVW/lASnyEJ6BfewJjADJ5dJXg")
	j = DecodeBase64OrDie("j0NDRmSPa5bfid2pAcUXaxCm2Dlh3TwayItZstwyeqQ")
	m = DecodeBase64OrDie("0/P6aJJJfbEKJBf86bVTRkzF0HcYQZ3otn5z5GDH2qs")
	r = DecodeBase64OrDie("zk6aDa0e7Y1pxxNpKnSea2xIb3kVbso8Lprm2yK2M+Y")

	// Third level
	g = DecodeBase64OrDie("qxaCpoXDD7YI8t2wA3thFGIWbjcPepuEO9nyR4X0P4Q")
	n = DecodeBase64OrDie("p9W1vm0JXk8Iaok7NQkUvpaFqdqQD/OXcvrgk8AoVsE")

	// Fourth level
	o = DecodeBase64OrDie("sMldWGNJuvhtsvs+SJ5bclJqVz1w8Ygv6aLLdZDEf/I")

	// MMR digest
	mmr = DecodeBase64OrDie("Oqoh2Jpmt0h6sLKErIRmjCYRpI3sZy3FIHfzCHl0qn4")
)

var hashN *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 0,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: b},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: a},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: c},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH, Index: 3},
	},
}

var bInO *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 1,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: n},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: f},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0}, // b
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: a},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
	},
}

var jInO *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 1,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: m},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0}, // j
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: g},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
	},
}

var bAndJInO *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 2,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: m},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1}, // j
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: f},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0}, // b
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: a},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_HASH_AND_PUSH},
	},
}

var MMRDigest *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 0,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: s},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: r},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: o},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH, Index: 3},
	},
}

type testCase struct {
	p      *hashmachine.Program
	inputs [][]byte
	output []byte
}

var testCases []testCase = []testCase{
	{hashInput, [][]byte{b}, DecodeBase64OrDie("PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0")},
	{hashN, [][]byte{}, DecodeBase64OrDie("N7OgVZ+dP0VRO9k8O/XxoBMIfbbz4tSxQs8ujGABv40")},
	{hashInput3, [][]byte{o, r, s}, mmr},

	// Second level
	{hashInput2, [][]byte{a, b}, c},
	{hashInput2, [][]byte{d, e}, f},
	{hashInput2, [][]byte{h, i}, j},
	{hashInput2, [][]byte{k, l}, m},
	{hashInput2, [][]byte{p, q}, r},

	// Third level
	{hashInput2, [][]byte{c, f}, g},
	{hashInput2, [][]byte{j, m}, n},

	// Fourth level
	{hashInput2, [][]byte{g, n}, o},

	// Inclusion proofs
	{bInO, [][]byte{b}, o},
	{jInO, [][]byte{j}, o},
	{bAndJInO, [][]byte{b, j}, o},

	// Digest
	{MMRDigest, [][]byte{}, mmr},
}

func TestProofs(t *testing.T) {
	for i, tc := range testCases {
		ok, out, err := hm.VerifyWithOutput(tc.p, tc.inputs, tc.output)
		if err != nil {
			t.Errorf("test case %d: %v", i, err)
		} else if !ok {
			t.Errorf("test case %d unequal output: expected %s, got %s", i, Encode(tc.output), Encode(out))
		}
	}
}
