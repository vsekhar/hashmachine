# hashmachine

Hashmachine is a simple and general protocol for hashing byte strings, useful when evaluating hash proofs from a number of sources (e.g. Merkle Trees).

Hashmachine programs are intended to support use cases where data is timestamped in a verifiable log and an inclusion proof (in hashmachine format) is later stored with the data. Protocol Buffers are used to ensure hashmachine program formats can evolve while maintaining compatibility (see below).

## Running hashmachine programs

Hashmachine encodes proofs as instructions to a stack machine

A Hashmachine program can be thought of logically as a function with the following signature:

```go
func hashMachineProgram(inputs [][]byte, ops []opcodes) ([]byte, error)
```

Programs consist of the following opcodes:

* `PUSH_INPUT(index uint32)`: pushes `input[index]` onto the stack and mark that input as "used"; fail if no such input exists
* `PUSH_BYTES(payload []byte)`: push a byte string literal onto the stack; fail if no byte string is provided in the program
* `POP_N_HASH_AND_PUSH(index uint32)`: pop `index` values from the stack, hashing each value in pop order, and pushing the hash result onto the stack; fail if the stack has insufficient values
  * This op code is useful for multi-valued top-level digests, like that of the MMR
* `POP_CHILDREN_HASH_AND_PUSH`: equivalent to `POP_N_HASH_AND_PUSH` where `N == metadata.branching_factor`.
  * This op code is useful for hashing a set of interior nodes to produce their parent
  * Having a separate op code saves us from repetitively storing the branching factor for this common case

All operations are executed sequentially and exactly once. There is no flow control.

All inputs provided to the program must be used exactly once by a call to `PUSH_INPUT`. Otherwise, the program is not valid.

After completing, exactly one byte string, representing the program output, must be left on the stack. If the stack is empty or has more than one value on it, the program is invalid and execution fails.

The output value can be compared to some expected value to validate the "proof" that the program encodes.

## Constructing hashmachine programs

Hashmachine programs are constructed by walking verifiable data structures to generate proofs linking some input value(s) to an expected output value.

The smallest valid hashmachine program simply hashes a single input:

```asm
Metadata{
    expected_input_count = 1
    branching_factor = 1
}
PUSH_INPUT(0)
POP_N_HASH_AND_PUSH
```

### Inclusion proofs

A more complex example might involve a client requesting a proof of inclusion for the value `b` in a binary Merkle tree summarized by `o`. In this tree, each non-leaf node is the hash of its two children from right to left.

```text
      ---- o ----
    /             \
    g              n
   /  \           /  \
 /     \         /    \
 c      f       j     m
/ \    / \     / \   / \
a  b  d   e   h   i k   l
```

To prove inclusion of `b` in `o`, the prover would provide values `a`, `f`, and `n` along with instructions on how to hash them together to produce `o`.

```asm
Metadata{
    expected_input_count = 1
    branching_factor = 2
}
PUSH_BYTES(a)
PUSH_INPUT(0)                 // == b (as input)
POP_CHILDREN_HASH_AND_PUSH    // hashes b, then a, pushes c
PUSH_BYTES(f)
POP_CHILDREN_HASH_AND_PUSH    // hashes f, then c, pushes g
PUSH_BYTES(n)
POP_CHILDREN_HASH_AND_PUSH    // hashes n, then g, pushes o
```

The client can then verify that the output of the above program matches `o`.

Intermediate (non-leaf) values can also be proven. The proof of inclusion for `j` in `o` is:

```asm
Metadata{
    expected_input_count = 1
    branching_factor = 2
}
PUSH_BYTES(g)
PUSH_INPUT(0)                 // == j (as input)
PUSH_BYTES(m)
POP_CHILDREN_HASH_AND_PUSH    // hashes m, then j, pushes n
POP_CHILDREN_HASH_AND_PUSH    // hashes n, then g, pushes o
```

Multiple input values can be proven in a single program. The proof for `[b, j]` in `o` is:

```asm
Metadata{
    expected_input_count = 2
    branching_factor = 2
}
PUSH_BYTES(a)
PUSH_INPUT(0)                 // == b (as input)
POP_CHILDREN_HASH_AND_PUSH    // hashes b, then a, pushes c
PUSH_BYTES(f)
POP_CHILDREN_HASH_AND_PUSH    // hashes f, then c, pushes g
PUSH_INPUT(1)                 // == j (as input)
PUSH_BYTES(m)
POP_CHILDREN_HASH_AND_PUSH    // hashes m, then j, pushes n
POP_CHILDREN_HASH_AND_PUSH    // hashes n, then g, pushes o
```

Proving multiple values reuses literals and intermediates, reducing the size of the proof. The proof for `b` alone had 3 literals and 7 operations, the proof for `j` alone had 2 literals and 5 operations, totalling 5 literals and 12 operations. The combined proof, however, only had 3 literals and 9 operations. For a given tree, combined proof lengths grow approximately `O(logn)` in the number of values being proven (i.e. the number of inputs).

### Consistency proofs

Whereas inclusion proofs demonstrate inclusion of a value in a summary, consistency proofs demonstrate inclusion of a prior summary in a future one.

Consider the Merkle mountain range below:

```text
      ---- o ----
    /             \
    g              n
   /  \           /  \
 /     \         /    \
 c      f       j     m      r
/ \    / \     / \   / \    /  \
a  b  d   e   h   i k   l   p  q   s

digest_1 = hash(s, r, o)
```

At a later time, the MMR may have the form:

```text
      ---- o ----
    /             \
    g              n            v
   /  \           /  \         /  \
 /     \         /    \       /    \
 c      f       j     m      r      u
/ \    / \     / \   / \    /  \   /  \
a  b  d   e   h   i k   l   p  q   s  t

digest_2 = hash(v, o)
```

We want to demonstrate that `digest_2` is _consistent_ with `digest_1`. To do this, we first must recreate `digest_1` using its underlying hashes and then proceed to recreate `digest_2` from those and additional hashes.

```asm
Metadata{
    expected_input_count = 1
    branching_factor = 2
}
PUSH_BYTES(o)
PUSH_BYTES(r)
PUSH_BYTES(s)
PEAK_N_PUSH_DIGEST(3)         // hashes s, r, o (left on stack), pushes digest_1
MATCH_INPUT(0)                // pop digest_1, match it with input 0

PUSH_BYTES(t)
POP_CHILDREN_HASH_AND_PUSH    // hashes t, then s, pushes u
POP_CHILDREN_HASH_AND_PUSH    // hashes u, then r, pushes v
POP_N_PUSH_DIGEST(2)          // hashes v, then o, pushes digest_2
```

> TODO: add PEAK/POP_N_PUSH_DIGEST as opcodes.

The top of the stack can then be compared with `digest_2` to complete the proof.

## Compatibility

> **Hashmachine is currently pre-alpha. The hashmachine format and semantics are not stable**

When hashmachine reaches 1.0, the format will be considered stable. This means programs encoded in hashmachine are guaranteed to verify or fail to verify consistently over time.

## Caveats

### Reusable sponges

Modern hashes like Keccak/SHA-3 use a sponge construction whereby reading output from the hash modifies internal hash state, and where output can be read from the hash multiple times.

While hashmachine can make use of hashes relying on sponge construction, hashmachine itself uses them as though they were legacy non-sponge hashes. That is, hashmachine opcodes can only be used to create programs that write to a hash function multiple times and perform a single final read from the hash before the internal hash state is discarded. This is in keeping with the use case of verifiable data structure proofs: hash state is not used by these data strucutures after a single parent node hash is read from them.
