# Drawing — Reverse Engineering

**CTF:** TexSAW
**Category:** Reverse Engineering
**Flag:** `texsaw{switch96959d49370}`

## Challenge

> drawing be like
>
> Flag format: texsaw{flag} ex: texsaw{orthogonal}

A single file was provided: `drawing.nro`

## Solution

### Step 1: Identify the file

```
$ file drawing.nro
drawing.nro: data
```

The `.nro` extension identifies this as a **Nintendo Switch homebrew executable** — an ARM64 binary using the NRO format built with devkitPro.

### Step 2: Initial triage

Running `strings` and `grep` for the flag found nothing directly. However, strings revealed the binary embeds OpenGL (`#version 330 core` shaders) and the application name `drawing`.

The vertex shader was simple — no matrix transforms, just pass-through:

```glsl
layout (location = 0) in vec3 aPos;
layout (location = 1) in vec3 aColor;
void main() {
    gl_Position = vec4(aPos, 1.0);
    ourColor = aColor;
}
```

This meant vertex coordinates were in NDC space (−1 to 1) directly — whatever is drawn, its shape is defined entirely by the vertex buffer data in the binary.

### Step 3: Find the embedded JPEG (red herring)

`binwalk` found a JPEG image at offset `0x5A8038`:

```
$ binwalk drawing.nro
5931064    0x5A8038    JPEG image data, JFIF standard 1.01
```

Extracting it revealed a 256×256 image of a Nintendo Switch console outline — this is just the **application icon** embedded in the NRO's NACP metadata, not the flag.

### Step 4: Find the vertex buffer data

The NRO sections were parsed manually:
- `.text`: `0x000000` – `0x40F000` (~4 MB, bulk is Mesa/OpenGL library)
- `.rodata`: `0x40F000` – `0x563000`
- `.data`: `0x563000` – `0x5A8000`

Scanning `.rodata` for contiguous runs of valid NDC-range floats found a large block at **`0x44bbb4`** containing **19,955 floats** with values in [−1.5, 1.5]. Starting at index 11 within this block, the data follows the `(x, y, z, r, g, b)` vertex layout with stride 24 bytes:

- `z = 0.0` for all vertices (flat 2D drawing)
- `r = g = b = 1.0` for all vertices (solid white)
- `x` spans `−0.89` to `0.88` (nearly full width)
- `y` spans `−0.024` to `0.032` (very thin band — text height)

3,324 vertices / 3 = **1,108 triangles** forming filled letter shapes.

### Step 5: Render the vertex data

A Python script extracted the vertices and rendered them onto a 4000×600 canvas, mapping NDC coordinates to pixels:

```python
import struct
from PIL import Image, ImageDraw

# Extract vertices at stride 6 starting from index 11
verts = []
i = 11
while i + 6 <= count:
    x, y, z, r, g, b = floats[i:i+6]
    if abs(z) < 0.01 and -1.5 <= x <= 1.5 and -1.5 <= y <= 1.5:
        verts.append((x, y, r, g, b))
    i += 6

# Render triangles
for i in range(0, len(verts)-2, 3):
    v0, v1, v2 = verts[i], verts[i+1], verts[i+2]
    draw.polygon([to_pix(*v[:2]) for v in (v0,v1,v2)], fill=(255,255,255))
```

The rendered image revealed the flag text drawn in a pixel/block font across the full width of the screen.

### Flag

```
texsaw{switch96959d49370}
```

The program literally **drew** the flag using OpenGL triangles — the vertex coordinates in the `.rodata` section spelled out the flag when rendered. The "drawing" was the answer.
