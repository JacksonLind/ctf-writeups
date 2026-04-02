# Lost My Keys — TexSAW CTF Writeup

**Category:** Forensics / Steganography
**Flag:** `texsaw{you_found_me_at_key}`

## Challenge Description

> I can't find my original house key anywhere! Can you help me find it? Here's a picture of my keys the nanny took before they were lost. It must be hidden somewhere!

**Given file:** `Temoc_keyring.png`

---

## Solution

### Step 1: Triage the provided image

```bash
file Temoc_keyring.png
exiftool Temoc_keyring.png
```

`exiftool` immediately flagged something suspicious:

```
Warning: [minor] Trailer data after PNG IEND chunk
```

PNG files end at the `IEND` chunk. Any data beyond that is hidden content.

### Step 2: Discover the embedded ZIP

```bash
binwalk Temoc_keyring.png
```

Output revealed a ZIP archive embedded at offset `0x25580B0`:

```
39157936   0x25580B0   Zip archive data, name: key/
39158002   0x25580F2   Zip archive data, name: key/Temoc_keyring(orig).png
41225449   0x2750CE9   Zip archive data, name: key/where_are_my_keys.png
43081984   0x2916100   End of Zip archive
```

### Step 3: Extract the ZIP

```python
with open('Temoc_keyring.png', 'rb') as f:
    data = f.read()

zip_start = data.find(b'PK\x03\x04', 39157936)
with open('embedded.zip', 'wb') as out:
    out.write(data[zip_start:])
```

```bash
unzip embedded.zip
```

This extracted two 1024×1024 RGB PNG files:
- `key/Temoc_keyring(orig).png` — the original image
- `key/where_are_my_keys.png` — a seemingly identical image

### Step 4: Compare the two images

```python
from PIL import Image
import numpy as np

orig  = np.array(Image.open('key/Temoc_keyring(orig).png').convert('RGB'))
where = np.array(Image.open('key/where_are_my_keys.png').convert('RGB'))

xored = np.bitwise_xor(orig, where)
diff_pixels = np.argwhere(np.any(xored != 0, axis=2))
print(len(diff_pixels), 'pixels differ')
```

Result: **131 pixels differ**, all located on **row 0**, all in the **red channel only**, each with XOR value of exactly `1` (i.e. a single LSB flip).

### Step 5: Decode the hidden message

The 131 modified pixel column positions act as a **positional bitmask** across the 1024-pixel-wide first row. Each column index is either "modified" (bit = 1) or "unmodified" (bit = 0), producing a 1024-bit (128-byte) sequence:

```python
diff_mask = np.any(xored[0] != 0, axis=1)  # 1024 booleans

result = bytearray()
for i in range(0, 1024, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | int(diff_mask[i + j])
    result.append(byte)

print(result.decode())
# texsaw{you_found_me_at_key}
```

---

## Summary

The challenge used three layers of hiding:

| Layer | Technique |
|-------|-----------|
| 1 | ZIP archive appended after PNG IEND chunk |
| 2 | Two visually identical images bundled inside the ZIP |
| 3 | Flag encoded as a positional LSB bitmask in row 0 of the red channel |

The key insight was that the differences weren't in the *values* of the modified pixels but in *which* pixels were modified — their column positions, read in order, spelled out the flag in binary.
