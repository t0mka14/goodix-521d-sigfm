# goodix521d — Linux driver for the Goodix 27c6:521d (GF5298) fingerprint sensor

A [libfprint](https://fprint.freedesktop.org/) driver for the Goodix GF5298
press sensor (USB `27c6:521d`) found in laptops such as the ASUS ROG Zephyrus
G14. It works with `fprintd`, so it can be used for GDM login and `sudo`.

The sensor sends raw 64×80 images over an encrypted link and does no matching
itself. This driver matches on the host with **SIGFM** (SIFT keypoints plus a
geometric consistency check). The sensor area is too small for
minutiae-based matching (NBIS): in testing, NBIS accepted other fingers.

**Status:** works day to day on one laptop. Treat it as experimental.

| | |
|---|---|
| Tested hardware | ASUS ROG Zephyrus G14 (GA401), sensor firmware `GFUSB_GM168SEC_APP_10019` |
| Same finger, single press | 5/10 live with a 16-press enrollment; offline, 20–24 presses gave 60–67%. The driver enrolls 32. PAM allows 3 tries. |
| Other finger | never accepted in testing: every impostor press scored 0 |
| libfprint | upstream v1.94.10 plus this driver |

## Requirements

- **Windows must still be installed** on the machine and must have set up the
  sensor at least once. The encryption key (PSK) lives in the sensor sealed
  with Windows DPAPI. It can only be unsealed on that Windows install, once.
  The sensor's factory calibration is also read from the Windows driver's
  data.
- Firmware `GFUSB_GM168SEC_APP_10019`. The driver refuses other versions.

## Safety

The driver never writes keys or firmware and **never resets the sensor**. An
MCU soft reset sent during development left the sensor unresponsive, in Windows
too, until the laptop was fully powered off. If the sensor ever stops
answering: shut down, hold the power button for 15 seconds, then boot again.

## Setup

### 1. Read the sealed key (Linux)

```sh
sudo apt install python3-usb
sudo systemctl stop fprintd
sudo python3 tools/read_sealed_key.py goodix-psk
```

This writes `goodix-psk/dpapi_blob.bin` (the sealed key) and
`goodix-psk/mcu_hash.txt` (the key's SHA-256). It only reads from the sensor.

### 2. Unseal it (Windows)

Copy `goodix-psk/` plus `tools/windows/unseal_psk.ps1` and
`tools/windows/run_child.cmd` to `C:\goodix-psk`. Then, in an
**Administrator** PowerShell:

```powershell
cd C:\goodix-psk
powershell -ExecutionPolicy Bypass -File .\unseal_psk.ps1
```

The key was sealed by the driver's service account. The script therefore
unseals it from short-lived scheduled tasks running as LOCAL SERVICE and then
SYSTEM, and removes the tasks afterwards. It saves `goodix.psk` only if the
result's SHA-256 matches the hash the sensor reported.

### 3. Build and install (Linux)

```sh
sudo apt install git meson ninja-build gcc g++ pkg-config \
  libglib2.0-dev libgusb-dev libgudev-1.0-dev libpixman-1-dev libssl-dev \
  libopencv-features2d-dev libopencv-imgproc-dev libopencv-core-dev
./build.sh
sudo ./install.sh --psk /mnt/win/goodix-psk/goodix.psk --windows /mnt/win
```

`install.sh` puts the key and the calibration in `/etc/goodix-521d/` (root
only, mode 600). It also installs libfprint into `/usr/local`, which takes
precedence over the distribution's copy. Replace `/mnt/win` with wherever the
Windows partition is mounted.

### 4. Enroll

```sh
fprintd-enroll        # 32 presses, see below
fprintd-verify
sudo pam-auth-update --enable fprintd   # optional: fingerprint for sudo/login
```

**Enrollment coverage is what makes matching work.** Each press only sees a
small patch of the finger. Across the 32 presses, deliberately cover the whole
fingertip: centre, tip, both edges, the lower part, and a few slightly rotated.
Most failed matches are presses on an area the enrollment never saw.

## How it works

- **Link:** the sensor is the TLS 1.2 client (PSK-AES128-CBC-SHA256). The
  driver checks the key against the hash the sensor reports, then sets up TLS
  on in-memory BIOs. It uploads the config, built from a template with three
  registers taken from the sensor's OTP, and captures at the DACs stored in
  the OTP.
- **Robust start:** a reply left over from an earlier session is drained and
  the link retried. Resets are never used.
- **Images:** at the capture DAC the empty sensor saturates, so a no-finger
  frame can't serve as a background. Instead, the background is the per-pixel
  median of all finger frames seen during enrollment, stored in the print and
  subtracted from every later frame. A local mean is removed and the contrast
  normalised before SIFT.
- **Matching (`driver/sigfm.cpp`):**
  - SIFT keypoints, then the Lowe ratio test (0.75);
  - count pairs of matches whose relative distance and angle agree (5%);
  - accept at 12 consistent pairs.
  - Genuine overlapping presses score from about 15 up to several hundred.
  - Other fingers score 0.
- **Prints:** about 400 KB each. They hold the background and up to 3 frames
  per enrollment press, and are stored by fprintd like any other print.
- The USB work runs in a worker thread, one press at a time, and cancellation
  is honoured between frames. That keeps fprintd responsive and the link in
  step.

## Files

| Path | |
|---|---|
| `driver/goodix521d.c` | the libfprint driver (USB, TLS, capture, enroll/verify/identify) |
| `driver/goodix521d_config.c` | sensor config from the OTP calibration |
| `driver/sigfm.cpp`, `sigfm.h` | the SIGFM matcher (OpenCV) |
| `libfprint-v1.94.10.patch` | registers the driver in libfprint's build |
| `build.sh`, `install.sh` | build against upstream libfprint, install key + calibration + library |
| `tools/read_sealed_key.py` | read-only dump of the sealed key and its hash |
| `tools/extract_otp.py` | copy the OTP calibration out of `goodix.dat` |
| `tools/windows/` | unseal the key on Windows |

## Uninstall

```sh
sudo ninja -C libfprint/build uninstall && sudo ldconfig
sudo rm -r /etc/goodix-521d
```

## Credits

- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump):
  the USB protocol and image format.
- [goodix-fp-linux-dev/sigfm](https://github.com/goodix-fp-linux-dev/sigfm):
  the matching algorithm (MIT).
- [jitendradara12/goodix-5e0a](https://github.com/jitendradara12/goodix-5e0a)
  and [its write-up](https://jitendra.is-a.dev/writings/goodix-blog/): getting
  the DPAPI-sealed key out of Windows.
- [neodyme: fingerprint reversing](https://neodyme.io/en/blog/fingerprint_reversing/)
- [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)

## License

LGPL-2.1-or-later, like libfprint (see `LICENSE`).
