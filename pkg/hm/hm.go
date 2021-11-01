// Package hm provides the implementation of the hash machine.
package hm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/vsekhar/hashmachine"
	"github.com/vsekhar/hashmachine/pkg/oncehash"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

type HashMachine struct {
	program *hashmachine.Program
	inputs  [][]byte

	ip    int
	h     oncehash.Hash
	stack [][]byte
}

func New(p *hashmachine.Program, inputs [][]byte) (*HashMachine, error) {
	if int(p.Metadata.ExpectedInputCount) != len(inputs) {
		return nil, fmt.Errorf("invalid input count: program expected %d, got %d", p.Metadata.ExpectedInputCount, len(inputs))
	}

	ext := proto.GetExtension(p.Metadata.HashConfig.HashFunction.Descriptor().Values().ByNumber(p.Metadata.HashConfig.GetHashFunction().Number()).Options(), hashmachine.E_OutputLength)
	v, ok := ext.(hashmachine.HashFunctionOutputLength)
	if !ok {
		panic(fmt.Sprintf("bad option value: %#v", v))
	}
	switch v {
	case hashmachine.HashFunctionOutputLength_HASHFUNCTIONOUTPUTLENGTH_UNKNOWN:
		return nil, fmt.Errorf("no hash function length option specified: %s", v)
	case hashmachine.HashFunctionOutputLength_HASHFUNCTIONOUTPUTLENGTH_FIXED:
		if p.Metadata.HashConfig.HashOutputLengthBytes != 0 {
			return nil, fmt.Errorf("fixed-length hash function '%s' has non-zero HashOutputLengthBytes %d", p.Metadata.HashConfig.HashFunction.String(), p.Metadata.HashConfig.HashOutputLengthBytes)
		}
	case hashmachine.HashFunctionOutputLength_HASHFUNCTIONOUTPUTLENGTH_VARIABLE:
		if p.Metadata.HashConfig.HashOutputLengthBytes == 0 {
			return nil, fmt.Errorf("variable-length hash function '%s' has zero HashOutputLengthBytes %d", p.Metadata.HashConfig.HashFunction.String(), p.Metadata.HashConfig.HashOutputLengthBytes)
		}
	}

	ret := &HashMachine{program: p, inputs: inputs}
	switch p.Metadata.HashConfig.HashFunction {
	case hashmachine.HashFunction_HASHFUNCTION_SHA_256:
		ret.h = oncehash.WrapHash(sha256.New())
	case hashmachine.HashFunction_HASHFUNCTION_SHA3_512:
		ret.h = oncehash.WrapShake(sha3.NewShake256(), int(p.Metadata.HashConfig.HashOutputLengthBytes))
	default:
		return nil, fmt.Errorf("unknown hash function: %s", p.Metadata.HashConfig.HashFunction.String())
	}

	return ret, nil
}

func (hm *HashMachine) push(b []byte) {
	hm.stack = append(hm.stack, b)
}

func (hm *HashMachine) pop() []byte {
	r := hm.stack[len(hm.stack)-1]
	hm.stack = hm.stack[:len(hm.stack)-1]
	return r
}

// Returns the value on the stack at index i (0 == top of stack).
func (hm *HashMachine) peak(i int) []byte {
	return hm.stack[len(hm.stack)-1-i]
}

func (hm *HashMachine) Output() ([]byte, error) {
	if len(hm.stack) != 1 {
		return nil, fmt.Errorf("invalid program: expected one output on stack, stack size: %d", len(hm.stack))
	}
	return hm.pop(), nil
}

func (hm *HashMachine) Step() error {
	if hm.ip >= len(hm.program.Ops) {
		return fmt.Errorf("ip advanced past end of program")
	}
	op := hm.program.Ops[hm.ip]
	hm.ip++
	switch op.Opcode {
	case hashmachine.OpCode_OPCODE_UNKNOWN:
		return errors.New("invalid program: opcode is UNKNOWN")
	case hashmachine.OpCode_OPCODE_PUSH_INPUT:
		if op.Index >= uint64(hm.program.Metadata.ExpectedInputCount) {
			return fmt.Errorf("invalid program: input index out of bounds %d, program's expected input count %d", op.Index, hm.program.Metadata.ExpectedInputCount)
		}
		if int(op.Index) >= len(hm.inputs) {
			// Shouldn't happen, we check inputs in New.
			return fmt.Errorf("invalid invocation: program expected input at index %d, invoked with %d total inputs", op.Index, len(hm.inputs))
		}
		hm.push(hm.inputs[op.Index])
	case hashmachine.OpCode_OPCODE_PUSH_BYTES:
		hm.push(op.Payload)
	case hashmachine.OpCode_OPCODE_POP_CHILDREN_PUSH_HASH:
		if hm.program.Metadata.BranchingFactor < 1 {
			return fmt.Errorf("bad branching factor in metadata: %d", hm.program.Metadata.BranchingFactor)
		}
		if len(hm.stack) < int(hm.program.Metadata.BranchingFactor) {
			return fmt.Errorf("invalid program: stack underflow, expected at least %d values, found %d", int(hm.program.Metadata.BranchingFactor), len(hm.stack))
		}
		hm.h.Reset()
		for i := 0; i < int(hm.program.Metadata.BranchingFactor); i++ {
			hm.h.Write(hm.pop())
		}
		hm.push(hm.h.Sum(nil))
	case hashmachine.OpCode_OPCODE_POP_N_PUSH_HASH:
		if len(hm.stack) < int(op.Index) {
			return fmt.Errorf("invalid program: stack underflow, expected at least %d values, found %d", int(op.Index), len(hm.stack))
		}
		hm.h.Reset()
		for i := 0; i < int(op.Index); i++ {
			hm.h.Write(hm.pop())
		}
		hm.push(hm.h.Sum(nil))
	case hashmachine.OpCode_OPCODE_PEAK_N_PUSH_HASH:
		if len(hm.stack) < int(op.Index) {
			return fmt.Errorf("invalid program: stack underflow, expected at least %d values, found %d", int(op.Index), len(hm.stack))
		}
		hm.h.Reset()
		for i := 0; i < int(op.Index); i++ {
			hm.h.Write(hm.peak(i))
		}
		hm.push(hm.h.Sum(nil))
	case hashmachine.OpCode_OPCODE_MATCH_INPUT:
		if op.Index >= uint64(hm.program.Metadata.ExpectedInputCount) {
			return fmt.Errorf("invalid program: input index out of bounds %d, program's expected input count %d", op.Index, hm.program.Metadata.ExpectedInputCount)
		}
		if int(op.Index) >= len(hm.inputs) {
			// Shouldn't happen, we check inputs in New.
			return fmt.Errorf("invalid invocation: program expected input at index %d, invoked with %d total inputs", op.Index, len(hm.inputs))
		}
		v := hm.pop()
		if !bytes.Equal(v, hm.inputs[op.Index]) {
			return fmt.Errorf("invalid program: value (%x) does not match input %d (%x)", v, op.Index, hm.inputs[op.Index])
		}
	default:
		return fmt.Errorf("invalid program: unknown opcode %d", op.Opcode)
	}
	return nil
}

func (hm *HashMachine) Done() bool {
	return hm.ip >= len(hm.program.Ops)
}

func VerifyWithOutput(prog *hashmachine.Program, inputs [][]byte, expected []byte) (ok bool, output []byte, err error) {
	hm, err := New(prog, inputs)
	if err != nil {
		return false, nil, err
	}
	for !hm.Done() {
		if err := hm.Step(); err != nil {
			return false, nil, err
		}
	}
	out, err := hm.Output()
	if err != nil {
		return false, out, err
	}
	return bytes.Equal(out, expected), out, nil
}

func Verify(prog *hashmachine.Program, inputs [][]byte, expected []byte) (ok bool, err error) {
	ok, _, err = VerifyWithOutput(prog, inputs, expected)
	return ok, err
}
