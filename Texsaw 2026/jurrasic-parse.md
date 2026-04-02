# Jurassic Parse 2 — Writeup

**Category:** Forensics / Steganography
**Flag:** `texsaw{Steg0s@urus_Eats_APL1eS}`

## Challenge Description

> I found this neat picture of my favorite dinosaur! I wonder what they eat...

A single file is provided: `STEGOSAURUS.png` (162×141 px, RGB).

## Solution

### Step 1: LSB Steganography

Standard triage (`strings`, `exiftool`, `binwalk`) found nothing. Extracting the 1-bit LSB from each RGB channel in interleaved order (R₀G₀B₀R₁G₁B₁…) and reassembling into bytes revealed hidden UTF-8 text:

```
(∊42⌽(3⍴⍴⍵)⍴⌽⌊/⍤1⊢⍉⌊⍵×255)[46 53 88 243 57 43 156 6 46 53 5 10 243 1 77 39 77 243 54 166 57 46 243 54 23 313 51 136 53 6 87]<<END>>
```

This is an **APL expression** followed by a list of 31 indices and a `<<END>>` sentinel. The index list selects characters from the result of the expression to spell out the flag.

### Step 2: Evaluating the APL Expression

The expression `(∊42⌽(3⍴⍴⍵)⍴⌽⌊/⍤1⊢⍉⌊⍵×255)` is evaluated with `⍵` = the image. The key insight is that APL treats the image as **channels-first** `(3, 141, 162)`.

Step-by-step (right-to-left, as APL evaluates):

| Step | Operation | Shape | Description |
|------|-----------|-------|-------------|
| 1 | `⌊⍵×255` | `(3, 141, 162)` | Floor of normalized pixels → integer values |
| 2 | `⍉` | `(162, 141, 3)` | Reverse axis order (transpose) |
| 3 | `⌊/⍤1` | `(162, 141)` | Min over channels for each pixel |
| 4 | `⌽` | `(162, 141)` | Reverse each row |
| 5 | `(3⍴⍴⍵)⍴` | `(3, 141, 162)` | Reshape (cycling 22,842 values to 68,526) |
| 6 | `42⌽` | `(3, 141, 162)` | Rotate last axis by 42 positions |
| 7 | `∊` | `(68526,)` | Flatten to 1D vector |

Then 1-based indexing with the 31 provided indices extracts the flag characters.

### Step 3: Python Implementation

```python
from PIL import Image
import numpy as np

img = Image.open('STEGOSAURUS.png')
arr = np.array(img)  # (141, 162, 3)

indices = [46, 53, 88, 243, 57, 43, 156, 6, 46, 53, 5, 10, 243, 1, 77,
           39, 77, 243, 54, 166, 57, 46, 243, 54, 23, 313, 51, 136, 53, 6, 87]

# ⍵ as channels-first
omega = np.transpose(arr, (2, 0, 1)).astype(float) / 255.0  # (3, 141, 162)

step1 = np.floor(omega * 255).astype(int)       # ⌊⍵×255
step2 = np.transpose(step1)                      # ⍉  → (162, 141, 3)
step4 = np.min(step2, axis=-1)                   # ⌊/⍤1 → (162, 141)
step5 = step4[:, ::-1]                           # ⌽
step6 = np.resize(step5.flatten(), 3*141*162).reshape(3, 141, 162)  # (3⍴⍴⍵)⍴
step7 = np.roll(step6, -42, axis=-1)             # 42⌽
flat  = step7.flatten()                          # ∊

flag = ''.join(chr(flat[i-1]) for i in indices)
print(flag)  # texsaw{Steg0s@urus_Eats_APL1eS}
```

## Flag

```
texsaw{Steg0s@urus_Eats_APL1eS}
```

The inner flag is a leet-speak pun: **Steg0s@urus Eats APL1eS** → *Stegosaurus Eats APLies* (the stegosaurus "eats" the image by having the APL expression **apply** to it). The challenge title "Jurassic **Parse**" points directly to parsing the APL expression hidden in the image's LSBs.
