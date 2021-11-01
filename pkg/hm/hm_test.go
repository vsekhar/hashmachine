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
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_PUSH_HASH, Index: 1},
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
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_PUSH_HASH, Index: 2},
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
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 2},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_PUSH_HASH, Index: 3},
	},
}

// The tests below use the following MMR, where leafs are just the
// corresponding letter and non-leafs are the hashes of their children.
//
// Two states are used: MMR1 (lowercase letters) and MMR2 (lowercase and
// bracketed uppercase letters).
//
//         ---- o ----
//       /             \
//       g              n           [V]
//      /  \           /  \         /  \
//     /    \         /    \       /    \
//    c      f       j     m      r     [U]
//   / \    / \     / \   / \    /  \   /  \
//   a  b  d   e   h   i k   l   p  q   s [T]

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
	T = []byte("T")

	// Second level
	c = DecodeBase64OrDie("lw9RnCytvO+x6BaU+QS8YindKoMA6YxtDU/Ev8pYQUA")
	f = DecodeBase64OrDie("nBYj8NOOKOlZTy7zGn7JCSkcT9sFp3fczS6Tan9AYBE")
	j = DecodeBase64OrDie("jGsK26VM3Fnc7eHnMn+966POJNXnTrhN+3IpflEuLas")
	m = DecodeBase64OrDie("xhHWo3lC8pk1RZUbKO7xJjT9l0CKll4uXe2/xOgVmcQ")
	r = DecodeBase64OrDie("y5aJe9D4L9VMJMk1huN0Fcg9XiXjiWQbl2017n1MxF4")
	U = DecodeBase64OrDie("2hM+C6myy73mjVnlR4gAUhi+EfoyfYdyrYPUGeb01Uo")

	// Third level
	g = DecodeBase64OrDie("aQicrrqFwNuwfMqNA+H8FyYqjIV6aWVku62qbNoCjv4")
	n = DecodeBase64OrDie("UvFKrAykGrv3JA/VEwYcDyzF7Y+NxYOAzy9YRCpKo/0")
	V = DecodeBase64OrDie("iLUkdfvPfSRNpBTFnzKq6w9Qd3Mm9V8gkEeGlDKTmMc")

	// Fourth level
	o = DecodeBase64OrDie("kZq0tPyMjPHXAlr4iHVgj5YiUn3Z/m0uCYG4gHZuVZQ")

	// MMR digests
	mmr1 = DecodeBase64OrDie("2MsldyyCLIWXHmoukhmBX9HT2mhB2WHzsbKOkunQS2k")
	mmr2 = DecodeBase64OrDie("yYYDbDjASjhExbut2BONfnra5Q3B5iZb5dre5uWXC6U")
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
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_PUSH_HASH, Index: 3},
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
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: a},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},   // b
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // c
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: f},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // g
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: n},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // o
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
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: g},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0}, // j
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: m},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // n
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // o
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
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: a},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},   // b
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // c
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: f},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // g
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1},   // j
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: m},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // n
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH}, // o
	},
}

var mmr1Digest *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 0,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: o},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: r},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: s},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_PUSH_HASH, Index: 3},
	},
}

var mmr2Digest *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 0,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: o},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: V},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_PUSH_HASH, Index: 2},
	},
}

var consistency *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		HashConfig: &hashmachine.HashConfig{
			HashFunction: hashmachine.HashFunction_HASHFUNCTION_SHA_256,
		},
		ExpectedInputCount: 1,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		// Reconstruct the digest(mmr1) (input[0])
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: o},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: r},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: s},
		{Opcode: hashmachine.OpCode_OPCODE_PEAK_N_PUSH_HASH, Index: 3}, // mmr1
		{Opcode: hashmachine.OpCode_OPCODE_MATCH_INPUT, Index: 0},

		// Construct digest(mmr2)
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: T},
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH},    // U
		{Opcode: hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH},    // V
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_PUSH_HASH, Index: 2}, // mmr2
	},
}

// TODO: consistency proof of mmr1 to mmr2

type testCase struct {
	p      *hashmachine.Program
	inputs [][]byte
	output []byte
}

var testCases []testCase = []testCase{
	{hashInput, [][]byte{b}, DecodeBase64OrDie("PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0")},
	{hashN, [][]byte{}, DecodeBase64OrDie("KCv+8LPxgJomsdbjPurWgEjfk1D76sQqR0c4z53/K/g")},

	// Second level
	{hashInput2, [][]byte{a, b}, c},
	{hashInput2, [][]byte{d, e}, f},
	{hashInput2, [][]byte{h, i}, j},
	{hashInput2, [][]byte{k, l}, m},
	{hashInput2, [][]byte{p, q}, r},
	{hashInput2, [][]byte{s, T}, U},

	// Third level
	{hashInput2, [][]byte{c, f}, g},
	{hashInput2, [][]byte{j, m}, n},
	{hashInput2, [][]byte{r, U}, V},

	// Fourth level
	{hashInput2, [][]byte{g, n}, o},

	// Inclusion proofs
	{bInO, [][]byte{b}, o},
	{jInO, [][]byte{j}, o},
	{bAndJInO, [][]byte{b, j}, o},

	// Digests
	{hashInput2, [][]byte{o, V}, mmr2},
	{hashInput3, [][]byte{o, r, s}, mmr1},
	{mmr1Digest, [][]byte{}, mmr1},
	{mmr2Digest, [][]byte{}, mmr2},

	// Consistency
	{consistency, [][]byte{mmr1}, mmr2},
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
