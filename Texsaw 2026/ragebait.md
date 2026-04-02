# Ragebait — Reverse Engineering Writeup

**CTF:** TexSAW
**Category:** Reverse Engineering
**Flag:** `texsaw{VVhYd_U_M4k3_mE_s0_4n6ry}`

---

## Overview

A stripped 64-bit ELF binary that takes a 32-character command-line argument and validates it. The challenge is aptly named — it's full of fake flags and decoy functions designed to waste your time.

---

## Initial Triage

```bash
file ragebait
# ELF 64-bit LSB executable, x86-64, stripped

strings ragebait | grep -i texsaw
# texsaw{nope_not_here}   ← first troll
```

Running the binary without arguments exits with code 1. A quick look at `main` reveals:

```
if argc <= 1 OR strlen(argv[1]) != 32:
    return 1
hash = FNV1a(argv[1][0:9]) % 1009
call table[hash](argv[1])
```

The binary requires a **32-character argument**, hashes the first 9 characters using FNV-1a, takes the result mod 1009, and dispatches to one of 1009 functions via a jump table at `0x44e080`.

---

## The Ragebait

Running `strings | grep texsaw` immediately reveals `texsaw{nope_not_here}` — a fake flag that's never even referenced in the code. Pure bait.

Further analysis finds **1009 unique functions** in the jump table. Three of them unconditionally decrypt and print a hardcoded string via `printf("[SUCCESS] Flag: %s", decrypted)`:

| Hash Slot | Flag |
|-----------|------|
| 0 | `texsaw{maybe_the_real_fake_flag_was_the_friends_we_made}` |
| 13 | `texsaw{fake_flag_do_not_submit}` |
| 90 | `texsaw{n0t_th3_fl4g_lol}` |

These three print the exact message from the SUCCESS format string — but the content literally says not to submit them. The other ~900 functions print fake bash-style error messages (e.g. `bash: Permission denied: <your_input>`, `Sir, this is a Wendy's.`, `Task failed successfully.`) regardless of input.

---

## Finding the Real Validator

Searching for the SUCCESS format string (`0x444020`) across all 1009 functions revealed **120 functions** containing a reference to it — but only 3 produced SUCCESS output when called with arbitrary input.

The other 117 must have a conditional path. Examining one of them at `0x42fe9c` (reachable via hash slot 714) revealed something completely different:

```asm
; Initialize 4 accumulators to 0
mov QWORD PTR [rbp-0x30], 0   ; acc[0]
mov QWORD PTR [rbp-0x28], 0   ; acc[1]
mov QWORD PTR [rbp-0x20], 0   ; acc[2]
mov QWORD PTR [rbp-0x18], 0   ; acc[3]

; Loop over all 32 chars of argv[1]
call strlen
; for i in 0..31:
;   acc[i%4] = acc[i%4] * 131 + (signed)argv1[i]
```

After the loop, the 4 accumulators are compared against hardcoded 64-bit targets:

```asm
cmp QWORD PTR [rbp-0x30], 0x0112996d9ae479fd  ; acc[0]
jne fail
cmp QWORD PTR [rbp-0x28], 0x00efb70b2a601818  ; acc[1]
jne fail
cmp QWORD PTR [rbp-0x20], 0x011c799cc5063ac2  ; acc[2]
jne fail
cmp QWORD PTR [rbp-0x18], 0x01100d35eadc1177  ; acc[3]
jne fail

; SUCCESS: print argv[1] as the flag
lea rsi, [rbp-0x78]          ; rsi = argv[1]
lea rdi, [SUCCESS_FORMAT]
call printf
```

If all 4 match: `printf("[SUCCESS] Flag: %s", argv[1])` — **argv[1] itself is the flag.**

---

## Solving the Hash

The hash is a **4-way interleaved polynomial hash** (mod 2⁶⁴):

```
acc[k] = c[k+0]*131^7 + c[k+4]*131^6 + c[k+8]*131^5 + ... + c[k+28]*131^0
```

where `k ∈ {0,1,2,3}` and each `c[i]` is a signed byte from argv[1].

Since the flag format is `texsaw{...}` with total length 32, positions 0–6 are `texsaw{` and position 31 is `}`. This fixes 8 of the 32 characters.

**Solving approach:** For each accumulator independently, subtract the known-character contributions from the target, then greedily assign the smallest valid ASCII character (32–126) to each unknown position from highest to lowest power:

```python
targets = [0x0112996d9ae479fd, 0x00efb70b2a601818,
           0x011c799cc5063ac2, 0x01100d35eadc1177]

known = {0:'t', 1:'e', 2:'x', 3:'s', 4:'a', 5:'w', 6:'{', 31:'}'}

for k in range(4):
    remaining = (target[k] - sum(known * powers)) % 2**64
    # greedy: pick smallest ASCII char at each position
    # that keeps the remaining achievable by future positions
```

This yields a valid 32-character flag that passes the binary's validation.

---

## Verification

```bash
$ ./ragebait 'texsaw{VVhYd_U_M4k3_mE_s0_4n6ry}'
[SUCCESS] Flag: texsaw{VVhYd_U_M4k3_mE_s0_4n6ry}
```

**Flag: `texsaw{VVhYd_U_M4k3_mE_s0_4n6ry}`**

Reading it aloud: *"Why'd U Make mE s0 4n6ry"* — fitting for a challenge called Ragebait.

---

## Summary

| Step | Finding |
|------|---------|
| `strings \| grep texsaw` | Fake flag `texsaw{nope_not_here}` — never referenced |
| Jump table dispatch | 1009 functions, selected by FNV-1a hash of first 9 chars mod 1009 |
| 3 unconditional SUCCESS functions | Print fake flags at slots 0, 13, 90 |
| ~900 "bash error" functions | Always print fake error + echo your input |
| Hidden validator at slot 714 | 4-way polynomial hash (×131) checks all 32 chars |
| Solve hash constraints | Greedy assignment yields the real flag |
