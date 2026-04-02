# Broken Quest — Writeup

**Category:** Reverse Engineering
**Flag:** `texsaw{1t_ju5t_work5_m0r3_l1k3_!t_d0e5nt_w0rk}`

---

## Overview

A 64-bit ELF binary simulating a quest game. You interact with 8 in-game objects to set quest objective flags, then turn in the quest to receive the flag. The twist: the quest is intentionally unsolvable through normal gameplay.

---

## Initial Triage

```bash
file brokenquest
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

checksec brokenquest
# Full RELRO, Stack Canary, NX, PIE — no obvious pwn path

strings brokenquest | grep -iE 'flag|texsaw|quest'
# "Interact with objects to advance your quest..."
# "handle_flag" (symbol visible — not stripped)
```

---

## Understanding the Binary

The program maintains an `int32_t arr[8]` state, initialized to all zeros. A menu offers 8 operations:

| Action | Operation |
|--------|-----------|
| Reset | `memset(arr, 0, 8)` |
| Rotate Pillars | Right-rotate all 8 elements |
| Increase Heat | `arr[0]++`, `arr[4]++` |
| Move Gold Coins | `arr[0] += 3`, `arr[3] -= 2` |
| Swing Sword | `arr[0] /= 5`, `arr[6] %= 5` |
| Swap Gems | swap `arr[0]` and `arr[5]` |
| Shift Sand Piles | `arr[1] <<= 1`, `arr[7] >>= 1` |
| Reverse Polarity | `arr[0] = -arr[0]`, `arr[2] = -arr[2]` |

**Turn in Quest** calls `turn_in(arr, target)`:

```c
// target = {2, 6, -4, 6, 0, 4, -3, 1}
if (memcmp(arr, target, 8) == 0) {
    handle_flag(arr);  // decodes and prints the flag
}
```

---

## The Broken Part

`memcmp` with size `8` checks only the **first 8 bytes** — `arr[0]` and `arr[1]`.
The win condition requires `arr[0] == 2` **and** `arr[1] == 6`.

**Problem:** `arr[1]` starts at `0`. The only operation that modifies it is **Shift Sand Piles** (`arr[1] <<= 1`). Left-shifting zero always yields zero — `arr[1]` can **never** reach 6. The quest is unsolvable by design.

---

## Solution — Method 1: GDB Patching

Break at `turn_in`, overwrite the state array with the target values, then let execution continue naturally:

```bash
cat > solve.gdb << 'EOF'
set pagination off
break turn_in
run
set *((int*)$rdi+0) = 2
set *((int*)$rdi+1) = 6
set *((int*)$rdi+2) = -4
set *((int*)$rdi+3) = 6
set *((int*)$rdi+4) = 0
set *((int*)$rdi+5) = 4
set *((int*)$rdi+6) = -3
set *((int*)$rdi+7) = 1
continue
quit
EOF

echo "0" | gdb -batch -x solve.gdb ./brokenquest
```

`memcmp` now passes, `handle_flag` receives the correct key state, and prints the flag.

---

## Solution — Method 2: Static Reverse Engineering

`handle_flag(state)` uses the state array as a key to XOR-decode an embedded ciphertext via the `transform`/`calc_val` functions. Knowing the required state `[2, 6, -4, 6, 0, 4, -3, 1]`, the decryption can be simulated entirely in Python without running the binary.

---

## Flag

```
texsaw{1t_ju5t_work5_m0r3_l1k3_!t_d0e5nt_w0rk}
```
