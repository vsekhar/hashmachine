# hashmachine
Hashmachine is a simple and general protocol for hashing byte strings, useful when evaluating hash proofs from a number of sources (e.g. Merkle Trees).

## Running hashmachine programs

Hashmachine encodes proofs as instructions to a stack machine

A Hashmachine program can be thought of logically as a function with the following signature:
```go
func hashMachineProgram(inputs [][]byte, ops []opcodes) ([]byte, error)
```

Programs consist of the following opcodes:

  * `PUSH_INPUT(index uint32)`: pushes `input[index]` onto the stack; fail if no such input exists
  * `PUSH_BYTES(payload []byte)`: push a byte string literal onto the stack; fail if no byte string is provided in the program
  * `POP_N_HASH_AND_PUSH`: pop `N` values from the stack, hashing each value in pop order, and pushing the hash result onto the stack; fail if the stack has insufficient values
    * This op code is useful for multi-valued top-level digests, like that of the MMR
  * `POP_CHILDREN_HASH_AND_PUSH`: equivalent to `POP_N_HASH_AND_PUSH` where `N == metadata.branching_factor`.
    * This op code is useful for hashing a set of interior nodes to produce their parent
    * Having a separate op code saves us from repetitively storing the branching factor for this common case

All operations are executed sequentially and exactly once. There is no flow control.

After all operations have been executed, exactly one byte string, representing the program output, must be left on the stack. If the stack is empty or has more than one value on it, the program is invalid and execution fails.

The output value can be compared to some expected value to validate the "proof" that the program encodes.

## Constructing hashmachine programs

Hashmachine programs are constructed by walking verifiable data structures to generate proofs linking some input value(s) to an expected output value.

The smallest valid hashmachine program simply hashes a single input:

```
Metadata{
    expected_input_count = 1
    branching_factor = 1
}
PUSH_INPUT(0)
POP_N_HASH_AND_PUSH
```

A more complex example might involve a client requesting a proof of inclusion for the value `b` in a binary Merkle tree summarized by `o`:

```
      ---- o ----
    /             \
    g              n
   /  \           /  \
 /     \         /    \
 c      f       j     m      r
/ \    / \     / \   / \    /  \
a  b  d   e   h   i k   l   p  q   s
```

To prove inclusion of `b` in `o`, the prover would provide values `a`, `f`, and `n` along with instructions on how to hash them together to produce `o`.

```
Metadata{
    expected_input_count = 1
    branching_factor = 2
}
PUSH_BYTES(n)
PUSH_BYTES(f)
PUSH_INPUT(0)          // == b (as input)
PUSH_BYTES(a)
POP_N_HASH_AND_PUSH    // hashes a, then b, pushes c
POP_N_HASH_AND_PUSH    // hashes c, then f, pushes g
POP_N_HASH_AND_PUSH    // hashes g, then n, pushes o
```

The client can then verify that the output of the above program matches `o`.

Intermediate (non-leaf) values can also be proven. The proof of inclusion for `j` in `o` is:

```
Metadata{
    expected_input_count = 1
    branching_factor = 2
}
PUSH_BYTES(m)
PUSH_INPUT(0)          // == j (as input)
POP_N_HASH_AND_PUSH    // hashes j, then m, pushes n
PUSH_BYTES(g)
POP_N_HASH_AND_PUSH    // hashes g, then n, pushes o
```

Multiple input values can be proven in a single program. The proof for `[b, j]` in `o` is:

```
Metadata{
    expected_input_count = 2
    branching_factor = 2
}
PUSH_BYTES(m)
PUSH_INPUT(1)          // == j (as input)
POP_N_HASH_AND_PUSH    // hashes j, then m, pushes n
PUSH_BYTES(f)
PUSH_INPUT(0)          // == b (as input)
PUSH_BYTES(a)
POP_N_HASH_AND_PUSH    // hashes a, then b, pushes c
POP_N_HASH_AND_PUSH    // hashes c, then f, pushes g
POP_N_HASH_AND_PUSH    // hashes g, then n, pushes o
```

Proving multiple values reuses literals and intermediates, reducing the size of the proof. The proof for `b` alone had 3 literals and 7 operations, the proof for `j` alone had 2 literals and 5 operations, totalling 5 literals and 12 operations. The combined proof, however, only had 3 literals and 9 operations. Combined proof length grows approximately `O(logn)` in the number of values being proven (i.e. the number of inputs).

## Caveats

### Reusable sponges

Modern hashes like Keccak/SHA-3 use a sponge construction whereby reading output from the hash modifies internal hash state, and where output can be read from the hash multiple times.

While hashmachine can make use of hashes relying on sponge construction, hashmachine itself uses them as though they were legacy non-sponge hashes. That is, hashmachine opcodes can only be used to create programs that write to a hash function multiple times and perform a single final read from the hash before the internal hash state is discarded. This is in keeping with the use case of verifiable data structure proofs: hash state is not used by these data strucutures after a single parent node hash is read from them.
