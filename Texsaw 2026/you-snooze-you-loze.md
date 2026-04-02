# You Snooze You Loze — OSINT Writeup

**Category:** OSINT
**Flag:** `texsaw{6_7}`

## Challenge Description

> D'oh, I overslept and missed most of the race! But wait, my friend took a picture while I was out, but I can't tell whose in the lead. Can you help me figure out the two cars that are in the lead? Usually they like to twin around this time of night...
>
> Flag format: `texsaw{(num_in_first)_(num_in_second)}` ex: `texsaw{21_44}`

## Files Provided

- `20260124_221412.zip` — contains a single JPEG: `20260124_221412.jpg`

## Solution

### Step 1: Extract and Triage

Unzipping the archive gives a single 8MB JPEG taken with a Samsung Galaxy S24 Ultra. The image shows a nighttime racing scene — cars on an illuminated oval track.

### Step 2: EXIF Metadata

Running `exiftool` on the image reveals two critical pieces of information:

```
Date/Time Original : 2026:01:24 22:14:12
GPS Position       : 29 deg 11' 4.79" N, 81 deg 4' 28.43" W
```

**GPS coordinates → Daytona International Speedway, Florida.**

Converting: 29.1847°N, 81.0746°W places the photo squarely inside the Daytona track complex.

### Step 3: Identifying the Event

The filename itself is a hint — `20260124_221412.jpg` encodes the date and time: **January 24, 2026 at 22:14:12**.

Cross-referencing with the racing calendar: the **2026 Rolex 24 at Daytona** (IMSA WeatherTech SportsCar Championship) started on the afternoon of January 24, 2026. At 22:14, the race was approximately **8 hours and 14 minutes** in.

### Step 4: Decoding the "Twin" Hint

The hint says *"they like to twin around this time of night."* This points to two **identical sister cars** from the same team running in formation.

At the 8-hour mark of the 2026 Rolex 24, **Porsche Penske Motorsport** had their two identical Porsche 963 GTP entries running 1–2:

| Position | Car # | Team                      | Car              | Drivers                                          |
|----------|-------|---------------------------|------------------|--------------------------------------------------|
| 1st      | **6** | Porsche Penske Motorsport | Porsche 963 GTP  | Kevin Estre / Laurens Vanthoor / Matt Campbell   |
| 2nd      | **7** | Porsche Penske Motorsport | Porsche 963 GTP  | Felipe Nasr / Julien Andlauer / Laurin Heinrich  |

These two cars are the "twins" — identical sister entries from the same manufacturer team, running nose-to-tail through the night.

Porsche Penske went on to claim their third consecutive Rolex 24 victory with car #6.

### Flag

```
texsaw{6_7}
```
