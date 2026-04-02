# Journaling — TexSaw CTF Forensics Writeup

**Category:** Forensics
**Flag:** `texsaw{u5njOurn@l_unc0v3rs_4lter3d_f1les_3fd19982505363d0}`

---

## Challenge Description

> I was using this Windows machine for journaling and notetaking, but I think malware got onto it. Can you take a look and put together any evidence left on disk?
>
> Note 1: Sufficient information is provided to figure out the order of flag segments
> Note 2: Flag segments should be connected by underscores and wrapped in texsaw{}
> Example flag format: `texsaw{part1_part2_part3}`

A link to a Google Drive file (`evidence.zip`) was provided.

---

## Overview

The challenge provides a 1 GB Windows NTFS disk image. Five flag segments are hidden across five different forensic artifact types, each requiring a different level of forensic analysis to uncover. The USN Journal timeline provides the correct ordering.

---

## Step 1: Acquire and Identify the Disk Image

Download and extract the archive:

```bash
wget "https://drive.usercontent.google.com/download?id=1A60AYTvSBW3Y4CMY8wnKgKjgW-y9UVbG&export=download&confirm=t" -O evidence.zip
unzip evidence.zip
file evidence.001
```

```
evidence.001: DOS/MBR boot record, MS-MBR Windows 7
```

Inspect the partition layout:

```bash
mmls evidence.001
```

```
Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000127   0000000128   Unallocated
002:  000:000   0000000128   0002091135   0002091008   NTFS / exFAT (0x07)
```

Single NTFS partition starting at sector 128. The volume name is `Challenge`.

---

## Step 2: Enumerate the Filesystem

Using The Sleuth Kit's `fls` to list all files (including deleted ones):

```bash
fls -r -o 128 evidence.001
```

Several interesting entries immediately stand out:

```
d/d 940-144-1:    flagsegment_u5njOurn@l/
r/r 942-128-1:    notetoself.txt
-/r * 944-128-1:  flagsegment_f1les.txt       ← deleted
r/r 943-128-1:    monitor.log
r/r 945-128-1:    tasks.txt
r/r 945-128-3:    tasks.txt:source            ← alternate data stream
```

A quick raw string search confirms additional segments:

```bash
strings -e l evidence.001 | grep "^flagsegment_"
```

```
flagsegment_4lter3d
flagsegment_f1les.txt
flagsegment_u5njOurn@l
flagsegment_unc0v3rs.txt
```

```bash
strings evidence.001 | grep "^flagsegment_"
```

```
flagsegment_3fd19982505363d0
```

Five unique flag segment values identified. The hunt is on for where each one lives.

---

## Step 3: Extract the USN Journal

The `$UsnJrnl:$J` stream (inode 936) is the key to both finding segments and determining their order.

```bash
icat -o 128 evidence.001 936-128-3 > usnjrnl.bin
```

Parsing the journal with Python reveals the full creation timeline of all flagsegment artifacts:

```
2026-01-24 00:25:02  flagsegment_u5njOurn@l  (inode 940)  CREATE
2026-01-24 00:25:05  flagsegment_unc0v3rs.txt (inode 942)  CREATE → DELETE
2026-01-24 00:25:10  monitor.log              (inode 943)  CREATE → TRUNCATE
2026-01-24 00:25:15  flagsegment_f1les.txt   (inode 944)  CREATE
2026-01-24 00:25:19  tasks.txt               (inode 945)  CREATE + ADS written
```

This timeline — explicitly referenced in `tasks.txt` as "create timeline of events" — gives the correct part ordering.

---

## Segment Recovery

### Part 1 — `u5njOurn@l` (Directory Name)

The directory `flagsegment_u5njOurn@l` (inode 940) is visible in `fls` output. It sits inside a suspicious path:

```
Program Files\Microsoft\OneDrive\ListSync\flagsegment_u5njOurn@l\
```

Malware hiding a folder inside a legitimate-looking OneDrive sync path. The folder name itself is the segment: **`u5njOurn@l`** (leetspeak for "USN Journal").

---

### Part 2 — `unc0v3rs` (Deleted File in USN Journal / $LogFile)

`flagsegment_unc0v3rs.txt` was created at inode 942 and immediately deleted. The inode was reused for `notetoself.txt`, so the file does not appear in `fls` output.

The filename is only recoverable from two places:

1. **USN Journal** (`$UsnJrnl:$J`) — the journal recorded the file creation before deletion
2. **$LogFile** — NTFS transaction log retains the filename in index record redo/undo data

```bash
strings -e l logfile.bin | grep flagsegment
```

```
flagsegment_unc0v3rs.txt
```

The filename is the segment: **`unc0v3rs`** (leetspeak for "uncovers").

---

### Part 3 — `4lter3d` (Cleared MFT Resident Data)

`monitor.log` (inode 943) was created, written to, and then its data was **truncated to 0 bytes** (USN reason `0x4` = `DATA_TRUNCATION`). `icat` returns nothing because the file's stated size is zero.

However, examining the raw MFT entry reveals the content is still physically present in the resident `$DATA` attribute — only the length field was zeroed:

```bash
# MFT entry for inode 943 is at:
# offset = partition_start + MFT_cluster * bytes_per_cluster + inode * 1024
# = 65536 + 87125*4096 + 943*1024 = 0x15550C00
```

Dumping the raw MFT entry at `0x15550C00`:

```
0120: ff ff ff ff 82 79 47 11 67 00 73 00 65 00 67 00  .....yG.g.s.e.g.
0130: 6d 00 65 00 6e 00 74 00 5f 00 34 00 6c 00 74 00  m.e.n.t._.4.l.t.
0140: 65 00 72 00 33 00 64 00 0d 00 0a 00 00 00 00 00  e.r.3.d.........
```

After `ff ff ff ff` (end-of-attributes marker), the remaining bytes decode as UTF-16LE: **`gsegment_4lter3d\r\n`** — the tail end of `flagsegment_4lter3d`.

The content is the segment: **`4lter3d`** (leetspeak for "altered").

---

### Part 4 — `f1les` (Deleted File, Visible in fls)

`flagsegment_f1les.txt` (inode 944) was deleted but its MFT entry was not overwritten. It appears in `fls` as:

```
-/r * 944-128-1:  flagsegment_f1les.txt
```

Extracting its content:

```bash
icat -o 128 evidence.001 944-128-1 | python3 -c "import sys; print(sys.stdin.buffer.read().decode('utf-16-le', errors='replace'))"
```

```
Must be deleted
```

The content is a red herring. The **filename** is the segment: **`f1les`** (leetspeak for "files").

---

### Part 5 — `3fd19982505363d0` (NTFS Alternate Data Stream)

`tasks.txt` itself contains the clue:

```
To Do: Image infected device and analyze in Autopsy, identify IoCs,
create timeline of events, find out where part 5 is...
```

The file has an alternate data stream (`tasks.txt:source`, inode 945-128-3) that is invisible to normal file viewers:

```bash
icat -o 128 evidence.001 945-128-3
```

```
flagsegment_3fd19982505363d0
```

The ADS content is the segment: **`3fd19982505363d0`**. This is the hardest artifact to find, requiring ADS-aware forensic tools — exactly what the tasks.txt "to-do" item hints at.

---

## Ordering the Segments

The `tasks.txt` gives two critical hints:
1. **"create timeline of events"** — use the USN Journal timestamps as the ordering
2. **"find out where part 5 is"** — the ADS segment is explicitly labeled Part 5

Sorting all five flagsegment artifacts by their USN Journal creation timestamp:

| Part | Time | Segment | Artifact | Forensic Technique |
|------|------|---------|----------|--------------------|
| 1 | 00:25:02 | `u5njOurn@l` | Directory name | Standard file listing |
| 2 | 00:25:05 | `unc0v3rs` | Deleted filename | USN Journal / $LogFile |
| 3 | 00:25:10 | `4lter3d` | Cleared file content | Raw MFT parsing |
| 4 | 00:25:15 | `f1les` | Deleted filename | Deleted file recovery |
| 5 | 00:25:19 | `3fd19982505363d0` | NTFS ADS | Alternate Data Streams |

The segments also form a coherent forensic statement in order:
> **"USN Journal uncovers altered files [hash]"**

---

## Flag

```
texsaw{u5njOurn@l_unc0v3rs_4lter3d_f1les_3fd19982505363d0}
```

---

## Tools Used

- `mmls` / `fsstat` — partition and filesystem metadata
- `fls` / `istat` / `icat` — file listing, metadata, and content extraction (The Sleuth Kit)
- `strings` — raw string search in disk image
- Python — USN Journal parsing, raw MFT byte analysis
