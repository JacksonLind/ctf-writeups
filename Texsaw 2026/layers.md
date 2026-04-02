# Layers — Forensics Writeup

**CTF:** TexSAW
**Category:** Forensics
**Flag:** `texsaw{m@try02HkA_d0!12}`

---

## Challenge Description

> It might be easier to go to an apple store.

We're given `layers.zip`.

---

## Solution

### Step 1: Unpack the outer zip

```
layers.zip
├── layers/.DS_Store        ← hint from the challenge description
├── layers/layer1.zip
├── layers/layer2.zip
└── layers/layer3.zip
```

The hint "apple store" immediately points to the `.DS_Store` file — a macOS Finder metadata file that records what files existed in a folder, including ones that have since been removed.

Parsing it with the `ds_store` Python library reveals a hidden file reference:

```python
import ds_store
with ds_store.DSStore.open('layers/.DS_Store', 'r') as d:
    for item in d:
        print(item)
# <ext4.img b'Iloc'>
```

So somewhere in these layers there's an `ext4.img` to find.

---

### Step 2: Layer 1 — macOS DMG

`layer1.zip` extracts without a password and contains `layer1.dmg` (an APFS disk image). Extracting with `7z` yields:

```
layer1_extracted/
├── clue.txt
├── README.txt
└── notes/
    ├── contacts.txt
    └── timeline.txt
```

`clue.txt` contains:

```
CASE FILE - IR-2026-0042
The next evidence archive is protected.

    L2_PASSWORD=unz1p_m3
```

---

### Step 3: Layer 2 — Windows VHDX

Extract `layer2.zip` with password `unz1p_m3` (requires `7z` — the zip uses a compression level that the system `unzip` can't handle):

```bash
7z x layer2.zip -p"unz1p_m3" -o./layer2_extracted/
```

This yields `evidence.vhdx` — a Windows NTFS disk image. Extracting it with `7z` surfaces several files including a hidden **NTFS Alternate Data Stream**:

```
report.txt:secret.bin
```

Reading its contents:

```
TDNfUEFTU1dPUkQ9bCFudXhfSTJfbjN4Nw==
```

Base64-decoding gives:

```
L3_PASSWORD=l!nux_I2_n3x7
```

---

### Step 4: Layer 3 — Linux ext4 Image

Extract `layer3.zip` with password `l!nux_I2_n3x7`:

```bash
7z x layer3.zip -p"l!nux_I2_n3x7" -o./layer3_extracted/
```

This yields `ext4.img` — the hidden file that `.DS_Store` told us to look for.

Inspecting the filesystem with `debugfs` reveals:

```
decoy_0, decoy_extra_1 ... decoy_extra_5
```

But parsing the raw directory block shows a **deleted entry** — `flag.txt` — still pointing to inode 13. The data block for that inode (block 1649) has been zeroed out. Classic red-herring / anti-forensics setup.

Scanning all non-zero blocks in the image, blocks 1105–1136 each contain 8 bytes of what turn out to be ext4 block tail checksums. Block **1137**, however, starts with the gzip magic bytes `\x1f\x8b`:

```python
import gzip

with open('ext4.img', 'rb') as f:
    f.seek(1137 * 4096)
    block = f.read(4096)

idx = block.find(b'\x1f\x8b')
print(gzip.decompress(block[idx:]))
# b'texsaw{m@try02HkA_d0!12}'
```

The flag was gzip-compressed and hidden in what appears to be an unused metadata block — surviving even after `flag.txt`'s data block was wiped.

---

## Flag

```
texsaw{m@try02HkA_d0!12}
```
