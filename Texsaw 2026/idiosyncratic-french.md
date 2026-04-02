# Idiosyncratic Fr*nch — Writeup

**Category:** Crypto + OSINT
**Flag:** `txsaw{georges_perec}`

---

## Challenge Description

> This chall's got a bit of history to it.
> First, crack this initial cryptogram. Now, apply OSINT tools to find who authors that original script.
> Flag format: txsaw{first_last}

---

## Step 1: Identifying the Cipher

The challenge file `ciphertext.txt` contains a substitution-ciphered paragraph. Initial triage:

- No `texsaw{}` in plaintext strings
- Not base64/hex/rot13
- Letter frequency analysis shows a non-standard distribution — points to a monoalphabetic substitution

Spotting short words and patterns:
- `n` (single letter) → `a`
- `ugnu` (repeated) → `that`
- `nak` → `and`
- `gnv` / `gnk` → `has` / `had`

This revealed the cipher structure: the alphabet is **split into two halves and each half is reflected within itself**:

| Half | Mapping |
|------|---------|
| a–n (positions 0–13) | position `p` → position `13 - p` |
| o–z (positions 14–25) | position `p` → position `39 - p` |

Full substitution table:

```
a↔n  b↔m  c↔l  d↔k  e↔j  f↔i  g↔h
o↔z  p↔y  q↔x  r↔w  s↔v  t↔u
```

---

## Step 2: Decryption

```python
def decrypt(c):
    if c.isalpha():
        lower = c.lower()
        p = ord(lower) - ord('a')
        plain_p = 13 - p if p <= 13 else 39 - p
        result = chr(ord('a') + plain_p)
        return result.upper() if c.isupper() else result
    return c

ciphertext = open('ciphertext.txt').read()
print(''.join(decrypt(c) for c in ciphertext))
```

**Output:**

> Noon rings out. A wasp, making an ominous sound, a sound akin to a klaxon or a tocsin, flits about. Augustus, who has had a bad night, sits up blinking and purblind. Oh what was that word (is his thought) that ran through my brain all night, that idiotic word that, hard as I'd try to pin it down, was always just an inch or two out of my grasp - fowl or foul or Vow or Voyal? - a word which, by association, brought into play an incongruous mass and magma of nouns, idioms, slogans and sayings...

---

## Step 3: Recognizing the Source

The plaintext contains **no letter 'e'** — every word, every sentence, zero e's. This is the defining characteristic of a **lipogram**.

This is the opening passage of ***A Void*** (*La Disparition*), a novel written entirely without the letter 'e'. The cipher is elegantly thematic: since `e` maps to `j`, and the original text contains no `e`, the letter `j` never appears in the ciphertext either.

The title hint "Idiosyncratic Fr\*nch" (Fr**e**nch — itself missing an 'e') confirms the connection.

---

## Step 4: OSINT

*La Disparition* was written in **1969** by **Georges Perec**, a French author and member of the **Oulipo** literary group, known for writing under strict formal constraints.

---

## Flag

```
txsaw{georges_perec}
```
