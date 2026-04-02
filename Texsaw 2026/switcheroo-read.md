# Switcheroo Read — Reverse Engineering Writeup

**CTF:** TexSAW
**Category:** Reverse Engineering
**Flag:** `texsaw{pAt1ence!!_W0rKn0w?}`

---

## Challenge Description

> Whoopsie, some wild functions started switching my string. Please determine a string to fit their confusion.
>
> Flag format: texsaw{string} ex: texsaw{confused_String}

**Files provided:** `switcheroo` (ELF 64-bit executable), `README.txt`

---

## Initial Triage

```bash
file switcheroo
# ELF 64-bit LSB executable, x86-64, stripped

strings switcheroo | grep -i texsaw
# (nothing - no embedded flag)

cat README.txt
# texsaw{test_flag}   <-- placeholder, not the real flag

./switcheroo
# Please make a compatible password:
echo "test" | ./switcheroo
# (no output - length check fails silently)
```

The binary:
- Reads up to 27 characters via `scanf("%27[^\n]", buf)`
- Checks `strlen(buf) == 27` — if not, exits silently
- Calls the main validation logic on the 27-char input

---

## Static Analysis

Using `r2` / `objdump` to disassemble, four key functions are identified:

| Address | Role |
|---------|------|
| `0x401850` | `main` — reads input, length check, calls validator |
| `0x401729` | `validate` — applies 7 transform passes + intermediate checks, then calls final check |
| `0x4012df` | `transform(s, n)` — the "switcher" function |
| `0x4011b6` | `rotate(s, n)` — string rotation by n positions |
| `0x4013fd` | `final_check(s)` — compares derived values, opens `README.txt` |

---

## Understanding the Transforms

### `rotate(s, n)` — `0x4011b6`

Copies the string, then for each index `i` from 0 to 26:
```
s_new[(i + n) % 27] = s_old[i]
```
This is a **right rotation by n positions**.

### `transform(s, n)` — `0x4012df`

Behavior depends on parity of `n`:

**Even n:**
1. For `i` in `0..n-1`: `s[(i * n) % 27] += n` (mod 256)
2. Then `rotate(s, n)`

**Odd n:**
1. `rotate(s, n)` first
2. Then for `i` in `0..n-1`: `s[(i + n) % 27] -= n` (mod 256)

### Transform Sequence in `validate` — `0x401729`

The 7 transforms applied in order, with intermediate checks interspersed:

```
T1: transform(s, 5)   [odd]
T2: transform(s, 6)   [even]
    CHECK: s[11] == 'o'
T3: transform(s, 13)  [odd]
    CHECK: s[14] == 'R'
T4: transform(s, 3)   [odd]
T5: transform(s, 24)  [even]
    CHECK: s[0] == 0x9b
    CHECK: s[26] in [0x73..0x77]
T6: transform(s, 10)  [even]
    CHECK: s[8] == 'Y'
    CHECK: s[11] == 'Y'
    CHECK: s[12] in [0x74..0x77]
T7: transform(s, 7)   [odd]
    CHECK: s[20] == 0xb5
    CHECK: s[13] == 's'
    → call final_check(s)
```

Each `CHECK` tests the string **in its current transformed state** — not the original input.

---

## Reverse-Engineering `final_check` — `0x4013fd`

This function receives the string after all 7 transforms (call it `s7`) and does two things:

### 1. Derive a 10-character string and compare to `"README.txt"`

The function computes a 10-byte derived string from specific positions of `s7`:

| Derived byte | Formula | Must equal |
|---|---|---|
| `d[0]` | `s7[0] - 0x21` | `'R'` (0x52) |
| `d[1]` | `s7[1] - 0x20` | `'E'` (0x45) |
| `d[2]` | `s7[2] - 0x28` | `'A'` (0x41) |
| `d[3]` | `(s7[3] + 4) * 2` | `'D'` (0x44) |
| `d[4]` | `s7[12] + 0x1c` | `'M'` (0x4d) |
| `d[5]` | `s7[11] - 0x66` | `'E'` (0x45) |
| `d[6]` | `s7[10] + 0x08` | `'.'` (0x2e) |
| `d[7]` | `s7[9] + 0x14` | `'t'` (0x74) |
| `d[8]` | `s7[8] - 0x07` | `'x'` (0x78) |
| `d[9]` | `-(s7[26] + 6) * 2` | `'t'` (0x74) |

The derived string `d` is `strcmp`'d against `"README.txt"` (found at `0x404060`). The string is then used as the filename for `fopen(d, "rb")`.

This gives us exact or near-exact values for `s7[0..3]`, `s7[8..12]`, `s7[26]`.

### 2. Read bytes from `README.txt` and compare strtol values

Four pairs of hex characters are derived from `s7` and parsed with `strtol(..., 16)`:

| Positions | Formula (high, low nibble) | strtol target |
|---|---|---|
| `s7[5]`, `s7[6]` | `-(s7[5]>>1)-2`, `s7[6]+4` | `0x57` |
| `s7[7]`, `s7[25]` | `s7[7]-0x2b`, `s7[25]-0x31` | `0x34` |
| `s7[24]`, `s7[23]` | `s7[24]+5`, `8-(s7[23]>>1)` | `0x61` |
| `s7[22]`, `s7[21]` | `s7[22]-0x0f`, `s7[21]-0x3d` | `0x29` |

Enumerating all 256 possible byte values for each position and filtering to valid hex characters with the correct nibble values yields:

```
s7[5]  ∈ {0x91, 0x92}     s7[6]  = 0x33
s7[7]  = 0x5e              s7[25] = 0x65
s7[24] = 0x31              s7[23] ∈ {0xad, 0xae}
s7[22] = 0x41              s7[21] = 0x76
```

---

## Solving with Z3

With all constraints collected — 16 exact `s7` values, 4 intermediate state checks, and 2 ambiguous positions — the system was fed into **Z3** for symbolic solving.

All 7 transforms were implemented symbolically using Z3 `BitVec(8)` arithmetic (which automatically handles mod-256 wraparound):

```python
def transform_sym(s, n):
    if n % 2 == 0:
        for i in range(n):
            j = (i * n) % 27
            s[j] = (s[j] + n) % 256   # Z3 BitVec mod-256 arithmetic
        s = rotate_right(s, n)
    else:
        s = rotate_right(s, n)
        for i in range(n):
            j = (i + n) % 27
            s[j] = (s[j] - n) % 256
    return s
```

Constraints added to Z3:
- All known `s7` byte values
- All intermediate state checks (`s2[11]='o'`, `s3[14]='R'`, etc.)
- Printable ASCII range for the input (`0x21`–`0x7e`)

Z3 returned the unique printable solution in seconds:

```
s0 = texsaw{pAt1ence!!_W0rKn0w?}
```

---

## Verification

```bash
echo 'texsaw{pAt1ence!!_W0rKn0w?}' | ./switcheroo
# Please make a compatible password: You have entered the flag
```

---

## Flag

```
texsaw{pAt1ence!!_W0rKn0w?}
```

---

## Key Takeaways

- The challenge name "Switcheroo" refers to the custom string-permutation + byte-shift transforms applied to the input.
- The intermediate `CHECK` conditions (buried mid-function between transform calls) are critical constraints — missing them leads to an over-constrained or under-constrained system.
- The filename `README.txt` being derived from the final transformed string was a clever misdirection — the provided `README.txt` is a decoy containing `texsaw{test_flag}`.
- Z3 with symbolic 8-bit arithmetic (`BitVec(8)`) is well-suited for this class of problem: all operations stay in byte range automatically, making constraint encoding straightforward.
