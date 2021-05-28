package hm_test

import (
	"bytes"
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
		Hash:               hashmachine.Hash_HASH_SHA256,
		ExpectedInputCount: 1,
		BranchingFactor:    1,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
	},
}

var hashInput2 *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		Hash:               hashmachine.Hash_HASH_SHA256,
		ExpectedInputCount: 2,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
	},
}

// The tests below use the following tree, where leafs are just the
// corresponding letter and non-leafs are the hashes of their children.
//
//         ---- o ----
//       /             \
//       g              n
//      /  \           /  \
//    /     \         /    \
//    c      f       j     m
//   / \    / \     / \   / \
//   a  b  d   e   h   i k   l

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

	// Second level
	c = DecodeBase64OrDie("+44g/C5MPySMYMOb1lLzwTRymLuXe4tNWQO4UFViBgM")
	f = DecodeBase64OrDie("lZpF1E5vz1g2HtAEaBVW/lASnyEJ6BfewJjADJ5dJXg")
	j = DecodeBase64OrDie("j0NDRmSPa5bfid2pAcUXaxCm2Dlh3TwayItZstwyeqQ")
	m = DecodeBase64OrDie("0/P6aJJJfbEKJBf86bVTRkzF0HcYQZ3otn5z5GDH2qs")

	// Third level
	g = DecodeBase64OrDie("qxaCpoXDD7YI8t2wA3thFGIWbjcPepuEO9nyR4X0P4Q")
	n = DecodeBase64OrDie("p9W1vm0JXk8Iaok7NQkUvpaFqdqQD/OXcvrgk8AoVsE")

	// Fourth level
	o = DecodeBase64OrDie("sMldWGNJuvhtsvs+SJ5bclJqVz1w8Ygv6aLLdZDEf/I")
)

var bInO *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		Hash:               hashmachine.Hash_HASH_SHA256,
		ExpectedInputCount: 1,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: n},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: f},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0}, // b
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: a},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
	},
}

var jInO *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		Hash:               hashmachine.Hash_HASH_SHA256,
		ExpectedInputCount: 1,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: m},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0}, // j
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: g},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
	},
}

var bAndJInO *hashmachine.Program = &hashmachine.Program{
	Metadata: &hashmachine.ProgramMetadata{
		Hash:               hashmachine.Hash_HASH_SHA256,
		ExpectedInputCount: 2,
		BranchingFactor:    2,
	},
	Ops: []*hashmachine.Op{
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: m},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 1}, // j
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: f},
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_INPUT, Index: 0}, // b
		{Opcode: hashmachine.OpCode_OPCODE_PUSH_BYTES, Payload: a},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
		{Opcode: hashmachine.OpCode_OPCODE_POP_N_HASH_AND_PUSH},
	},
}

type testCase struct {
	p      *hashmachine.Program
	inputs [][]byte
	output []byte
}

var testCases []testCase = []testCase{
	// Passthrough
	{hashInput, [][]byte{b}, DecodeBase64OrDie("PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0")},

	// Second level
	{hashInput2, [][]byte{a, b}, c},
	{hashInput2, [][]byte{d, e}, f},
	{hashInput2, [][]byte{h, i}, j},
	{hashInput2, [][]byte{k, l}, m},

	// Third level
	{hashInput2, [][]byte{c, f}, g},
	{hashInput2, [][]byte{j, m}, n},

	// Fourth level
	{hashInput2, [][]byte{g, n}, o},

	// Inclusion proofs
	{bInO, [][]byte{b}, o},
	{jInO, [][]byte{j}, o},
	{bAndJInO, [][]byte{b, j}, o},
}

func TestProofs(t *testing.T) {
	for i, tc := range testCases {
		hm, err := hm.New(tc.p, tc.inputs)
		if err != nil {
			t.Fatalf("test case %d: %v", i, err)
		}
		for !hm.Done() {
			if err := hm.Step(); err != nil {
				t.Errorf("test case %d: %v", i, err)
			}
		}
		out, err := hm.Output()
		if err != nil {
			t.Fatalf("test case %d: %v", i, err)
		}

		if !bytes.Equal(out, tc.output) {
			t.Errorf("test case %d unequal output: expected %s, got %s", i, Encode(tc.output), Encode(out))
		}
	}
}
