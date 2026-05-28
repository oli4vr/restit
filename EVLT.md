# Entropy Vault (EVLT) — restit Cryptographic Storage

## Purpose

The Entropy Vault system stores sensor scripts and the sensor manifest (CSV) in
encrypted form on disk so that plaintext never touches disk after the initial
build phase. This prevents casual tampering with sensor scripts at rest.

---

## Vault File Format

Each vault file (e.g. `.restit.default.manifest`, `.restit.oschecks.manifest`)
is a sequence of fixed-size **entries**, each exactly **8192 bytes**:

```
┌──────────────────────────────────────────────┐
│  Payload (8128 bytes)                        │
│  ┌──────┬──────────────────┬──────────────┐  │
│  │ 2 B  │  random padding   │  plaintext   │  │
│  │offst │  (variable)       │  (null-term) │  │
│  └──────┴──────────────────┴──────────────┘  │
├──────────────────────────────────────────────┤
│  SHA-512 digest (64 bytes) of payload        │
└──────────────────────────────────────────────┘
```

Offset | Size | Field
-------|------|------
0      | 2    | `uint16_t` obscuring offset — random value pointing to where the plaintext starts within the 8128-byte payload (range: 2 .. 8125-len)
2..N   | var  | Random padding bytes (filled via `rand()`)
N..M   | var  | Plaintext null-terminated string
0..8127| 8128 | Entire payload is **double-encrypted** before writing
8128   | 64   | SHA-512 digest of the (encrypted) bytes 0–8127 — used for entry identification

The SHA-512 digest is computed **after** encryption and stored alongside,
so decryption + hash verification serves as the search mechanism.

---

## Layout on Disk

After `make bundle` or `restit -b main.yml`, vault files reside under
`~/.restit/` (or `./.restit/` in local mode):

```
.restit/
├── .restit.default.manifest   # Contains encrypted CSV content, 1 entry
├── .restit.oschecks.manifest  # Contains scripts in the oschecks category
├── .restit.performance.manifest
└── restit.cfg                 # INI config (not encrypted)
```

---

## Encryption — `encrypt.c`

The cipher is a custom symmetric block transform operating on the full
8128-byte payload as a single block. It uses a **1024-byte key** expanded
from the passphrase.

### Key Expansion (`buildkey`)

1. The input keystring is **exploded** to 1024 bytes using a simple modular
   arithmetic expansion that mixes each byte of the keystring with a running
   checksum:
   ```
   cval = ((n>>8) + (n&255) ^ last ^
           ((n&1) ? (cval+cur+1)&255 : (cval-cur-127))) & 255
   ```
2. The 1024-byte result is **SHA-512 hashed 16 times** (each 64-byte chunk
   produces one 64-byte hash block), yielding the final 1024-byte key.

### Substitution Tables (`buildtrans`)

From the key, **256 substitution tables** (each a permutation of bytes 0–255)
are derived, one per "phase". Each phase corresponds to `key[n]` (the n-th
byte of the key). An inverse decryption table (`dtable`) is also built.

### Per-Round Operations

Each encryption round applies four operations in sequence:

1. **InvertXOR** — XOR each byte with the complement of the key byte
   (`*spp ^ *key ^ 0xFF`). Equivalent to XOR with `~key`.
2. **Byte substitution** (`translate_fw`) — replace each byte using the
   substitution table for the current phase (`ttable[phase][byte]`).
3. **Left bit-rotation** (`obscure_fw`) — rotate 64-bit words left by a
   variable amount derived from the substitution table at `ttable[sc>>4] & 63`.
   The first and last words use `ttable[0]` and `ttable[1]`.
4. **Right bit-rotation** (`obscure_bw`) — rotate 64-bit words right
   (inverse of step 3), using phase `key[(n+512) & 1023]`.

```
encrypt_data(buffer, len):
  invertxor()
  for each round n:
    translate_fw(key[n])
    obscure_fw(key[n])
    invertxor()
    obscure_bw(key[(n+512) & 1023])
```

```
decrypt_data(buffer, len):
  for each round n (reverse order):
    obscure_fw(key[(n+512) & 1023])
    invertxor()
    obscure_bw(key[n])
    translate_bw(key[n])
  invertxor()
```

### Round Counts

| Data         | Rounds | Constant in code |
|-------------|--------|------------------|
| Manifest CSV | 16     | `entropy_append(..., 16)` / `entropy_search(..., 16)` |
| Scripts      | 2      | `entropy_append(..., 2)` / `entropy_search(..., 2)` |

---

## Vault Operations

### Writing — `entropy_append()`

```
wipe_buffer(payload)            ← fill 8128 bytes with rand()
obscure_offset = random(2 .. 8125 - strlen(data))
memcpy(payload + obscure_offset, data)
sha512(payload) → digest       ← stored at payload+8128
init_encrypt(password, rounds)  ← first encryption layer
encrypt_data(payload, 8192)
init_encrypt(keystring, rounds) ← second encryption layer
encrypt_data(payload, 8192)
fwrite(payload, 8192, file)    ← append to vault file
```

### Reading — `entropy_search()`

```
for each 8192-byte block in vault file:
  memcpy(temp, block)
  init_encrypt(keystring, rounds)  ← decrypt outer layer
  decrypt_data(temp, 8192)
  init_encrypt(password, rounds)   ← decrypt inner layer
  decrypt_data(temp, 8192)
  sha512(temp[0..8127]) → computed_digest
  if computed_digest == temp[8128..8191]:
    offset = *(uint16_t*)temp
    plaintext = temp[offset]
    return plaintext
return NULL  ← not found
```

> **Note**: This is a linear scan — each entry must be decrypted and
> hash-verified until a match is found. The hash acts as the entry
> identifier. Efficiency is acceptable for the small number of entries
> (typically <100).

### Other Operations

- **`entropy_replace()`** — seeks to a known offset in the vault file and
  overwrites an entry (same encrypt-then-write flow).
- **`entropy_erase()`** — overwrites an entry at a given offset with random
  bytes (no encryption).

---

## Integration in restit — `main.c`

### Build Phase (`restit -b main.yml`)

`generate_manifesto()` in `main.c`:

1. Opens `main.yml`, parses each line into `cmdsched` structs
2. The full CSV text is encrypted + appended to `.restit.default.manifest`
   using `entropy_append(yml, "manifest.yml", securestr, ..., 16)`
3. Each script file is encrypted + appended to its category vault file
   using `entropy_append(script, category_name, securestr, ..., 2)`

### Run Phase (`restit` daemon)

`load_manifesto()` in `main.c`:

1. Opens `.restit.default.manifest` vault file
2. Calls `entropy_search(yml_buf, "manifest.yml", securestr, vaultfile, 16)`
   to retrieve the decrypted CSV into memory
3. Parses the CSV to rebuild `cmdsched` structs (mode=1)
4. For each schedule, retrieves the script from its vault file:
   `entropy_search(commands, category, securestr, vaultfile, 2)`
5. Scripts remain in memory (`cmdsched->commands`) and are executed via
   `popen(c->shell, "w")` — piping the commands to the shell's stdin

### The Two Keys

| Role | Value | Used where |
|------|-------|------------|
| **Password** | `securestr` (64-byte hardcoded string in `main.h`) | Always the inner encryption layer |
| **Keystring** | `"manifest.yml"` for the YAML manifest, or the **category name** for scripts | Always the outer encryption layer |

---

## Known Weaknesses (acknowledged by author)

1. **Hardcoded password** — `securestr` in `main.h` is compiled into the
   binary. Anyone with the binary can extract it. The author plans to
   improve this in a future release.

2. **Custom cipher** — The encryption is a home-grown design, not a
   standard like AES. While it uses SHA-512 for key derivation and
   integrity, the core cipher has not been cryptanalyzed.

3. **Custom key expansion** — The `buildkey()` function uses a simple
   modular arithmetic expansion rather than a proper KDF (bcrypt,
   PBKDF2, Argon2). The post-expansion SHA-512 pass does add a layer
   of hardening.

4. **Plaintext on disk during build** — During `-b` mode, the source
   `main.yml` and script files are read from unencrypted files on disk.
   Only the vault files written afterward are encrypted.

5. **Linear scan search** — `entropy_search()` decrypts every entry in
   the vault file sequentially. With only a handful of entries this is
   fine, but it does not scale.

---

## Summary Data Flow

```
                         BUILD MODE
┌──────────┐    ┌─────────────────┐    ┌──────────────────┐
│ main.yml │───▶│ generate_       │───▶│ .restit.default. │
│ (plain)  │    │ manifesto()     │    │ manifest (enc)   │
└──────────┘    │                 │    └──────────────────┘
                │ entropy_append  │
┌──────────┐    │ (yml,           │    ┌──────────────────┐
│ df.sh    │───▶│  "manifest.yml",│───▶│ .restit.oschecks │
│ (plain)  │    │  securestr, 16) │    │ .manifest (enc)  │
└──────────┘    └─────────────────┘    └──────────────────┘

                         RUN MODE
┌──────────────────┐    ┌─────────────────┐    ┌──────────┐
│ .restit.default. │───▶│ load_manifesto()│───▶│ YAML     │
│ manifest (enc)   │    │ entropy_search  │    │ in mem   │
└──────────────────┘    │ ("manifest.yml",│    └──────────┘
                        │  securestr, 16) │
┌──────────────────┐    │                 │    ┌──────────┐
│ .restit.oschecks │───▶│ entropy_search  │───▶│ script   │
│ .manifest (enc)  │    │ (category,      │    │ in mem   │
└──────────────────┘    │  securestr, 2)  │    └──────────┘
                        └─────────────────┘          │
                                                     ▼
                                              popen(shell, "w")
                                              script → pipe → stdout
                                              parsed into result_record[]
```
