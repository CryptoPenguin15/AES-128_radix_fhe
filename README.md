# Design

- **Readable:** Close to the FIPS-197 documentation.
- **Encrypt/decrypt:** 
  - Default CTR encrypt mode.
  - OFB mode with both operations also supported. Each block is outsourced to the cloud, with a fresh key pair.
- **Efficient Implementation:**
  - Minimize bootstraps, as they dominate runtime.
  - Use MatchValues for the `S-Box` and at the `MixColumns` step.
- **xor:** Performed unchecked() since bitlength is known.
- **mix_col:**
   - Operations are decomposed.
   - Example: The complete g2 state and g3 state are first retrieved, and the g2_g3_xor state afterwards. 
- **Key Expansion:** 
  - Performed as an offline phase.
- **Parallelism:**
  - Support for 16 threads throughput, one per state.
- **Mode of Operation:**
   - Cipher mode OFB (Output Feedback) style, to XOR the stream.
   - `Encrypt(IV/the_message, key) -> Encrypt(#, key)`

### State matrix indices
#### byte layout

| Row/Col | 0  | 1  | 2  | 3  |
|---------|----|----|----|----|
| **0**   | 0  | 4  | 8  | 12 |
| **1**   | 1  | 5  | 9  | 13 |
| **2**   | 2  | 6  | 10 | 14 |
| **3**   | 3  | 7  | 11 | 15 |

## Work performed
### Operations

| Operation    | OPs Count | OPs / thread | Details              |
|--------------|-----------|--------------|----------------------|
| **add_key**  | 16        | 1            | bitwise XOR          |
| **sub_**     | 16        | 1            | One MatchValues      |
| **rot_rows** | 0         | 0            |                      |
| **mix_cols** | 80        | 5            | Two MVs, three XORs  |

### Encrypt
Time taken can be estimated from

| Operation    | Tot. operations | OPs / thread | 
|--------------|-----------------|--------------|
| **add_key**  | 11              | 11           |
| **sub_**     | 10              | 10           |
| **rot_rows** | 10              | 0            |
| **mix_cols** | 9 * 5           | 225          |
| **Total**    | **76**          | **246**      |      


## Example Invocation
### Binary
```bash
cargo run --release -- --help

Usage: aes128_rdx_fhe [OPTIONS]

Options:
  -n, --number-of-outputs <number_of_outputs>
          Sets the number of blocks [default: 1]
  -i, --initialization-vector <iv>
          Initialization vector [default: 0123456789abcdef]
  -k, --key <key>
          Key value [default: 000102030405060708090a0b0c0d0e0f]
  -h, --help
          Print help
  -V, --version
          Print version
```

```bash
cargo run --release -- -n 1 -i "0123456789abcdef" -k "0123456789abcdef0123456789abcdef"
```

### Test suite
Running all the tests at once probably overloads the system.
```bash
cargo test --release -- --nocapture
```
Cherry-pick tests with
```
cargo test --release -- --nocapture ::test_endianess -- --exact
```

# References
- [NIST FIPS 197 (Original)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
- [NIST FIPS 197 (Update 1)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [NIST Special Publication 800-38A](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf)
