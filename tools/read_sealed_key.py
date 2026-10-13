#!/usr/bin/env python3
"""Read the Windows-sealed TLS key and its hash from a Goodix 27c6:521d.

    sudo systemctl stop fprintd
    sudo python3 read_sealed_key.py OUTDIR

Writes OUTDIR/dpapi_blob.bin (the key, sealed with Windows DPAPI) and
OUTDIR/mcu_hash.txt (SHA-256 of the key, used to check the unsealed result).
Copy OUTDIR to the Windows partition and unseal it there with
tools/windows/unseal_psk.ps1.

Read-only: it sends NOP, a firmware-version query and preset-PSK reads.
It never resets the sensor or writes to it.

Needs pyusb (apt install python3-usb).
"""
import os
import struct
import sys

import usb.core
import usb.util

VID, PID = 0x27c6, 0x521d
EP_OUT, EP_IN = 0x01, 0x83
FIRMWARE = 'GFUSB_GM168SEC_APP_10019'
SLOT_HASH = 0xbb020001
SLOT_SEALED = 0xbb010002
CHUNK = 256


class Sensor:
    def __init__(self):
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            sys.exit('Goodix 27c6:521d not found')
        if self.dev.is_kernel_driver_active(0):
            self.dev.detach_kernel_driver(0)
        usb.util.claim_interface(self.dev, 0)
        self.drain()

    def drain(self):
        """Drop replies a previous session left queued."""
        for _ in range(50):
            try:
                self.dev.read(EP_IN, 0x10000, 100)
            except usb.core.USBTimeoutError:
                return

    def write(self, cmd, payload, checksum=True):
        proto = bytes([cmd]) + struct.pack('<H', len(payload) + 1) + payload
        proto += bytes([(0xaa - sum(proto)) & 0xff if checksum else 0x88])
        head = bytes([0xa0]) + struct.pack('<H', len(proto))
        data = head + bytes([sum(head) & 0xff]) + proto
        data += b'\0' * (-len(data) % 64)
        for i in range(0, len(data), 64):
            self.dev.write(EP_OUT, data[i:i + 64], 2000)

    def read(self, cmd):
        data = bytes(self.dev.read(EP_IN, 0x10000, 2000))
        if len(data) < 4 or data[0] != 0xa0 or sum(data[:3]) & 0xff != data[3]:
            raise IOError('invalid message pack')
        n = struct.unpack_from('<H', data, 1)[0]
        p = data[4:4 + n]
        length = struct.unpack_from('<H', p, 1)[0]
        if p[0] != cmd or p[2 + length] != (0xaa - sum(p[:2 + length])) & 0xff:
            raise IOError(f'invalid reply to command {cmd:#x}')
        return p[3:2 + length]

    def command(self, cmd, payload):
        self.write(cmd, payload)
        ack = self.read(0xb0)
        if ack[0] != cmd or not ack[1] & 1:
            raise IOError(f'no ACK for command {cmd:#x}')
        return self.read(cmd)

    def nop(self):
        self.write(0x00, b'\0\0\0\0', checksum=False)
        try:
            self.dev.read(EP_IN, 0x10000, 100)
        except usb.core.USBTimeoutError:
            pass

    def firmware(self):
        return self.command(0xa8, b'\0\0').split(b'\0')[0].decode()

    def psk_read(self, slot, length, offset):
        r = self.command(0xe4, struct.pack('<IIII', length, offset, slot, 0))
        if len(r) < 9 or r[0] != 0:
            raise IOError(f'slot {slot:#x} not readable')
        n = struct.unpack_from('<I', r, 5)[0]
        return r[9:9 + n]


def dpapi_length(blob):
    """Total length of a DPAPI blob, from its header fields."""
    p = 4 + 16 + 4 + 16 + 4                  # version, provider, mk version, mk guid, flags
    def field():
        nonlocal p
        n = struct.unpack_from('<I', blob, p)[0]
        p += 4 + n
    field()                                  # description
    p += 8                                   # crypt alg id, key length
    field()                                  # salt
    field()                                  # HMAC key
    p += 8                                   # hash alg id, hash length
    field()                                  # HMAC
    field()                                  # encrypted data
    field()                                  # signature
    return p


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)

    s = Sensor()
    s.nop()
    fw = s.firmware()
    print('firmware', fw)
    if fw != FIRMWARE:
        sys.exit(f'untested firmware {fw!r}, stopping')

    key_hash = s.psk_read(SLOT_HASH, 32, 0)
    # The slot is read in chunks; length fields not read yet count as 0, so
    # read and recompute until the blob's own length is covered.
    sealed = s.psk_read(SLOT_SEALED, CHUNK, 0)
    while True:
        total = dpapi_length(sealed + b'\0' * 4096)
        if len(sealed) >= total and dpapi_length(sealed[:total] + b'\0' * 4096) == total:
            break
        part = s.psk_read(SLOT_SEALED, min(CHUNK, total + 4 - len(sealed)), len(sealed))
        if not part:
            sys.exit('sealed key ended early')
        sealed += part
    sealed = sealed[:total]

    open(os.path.join(out, 'mcu_hash.txt'), 'w').write(key_hash.hex() + '\n')
    open(os.path.join(out, 'dpapi_blob.bin'), 'wb').write(sealed)
    print(f'sealed key: {len(sealed)} bytes -> {out}/dpapi_blob.bin')
    print(f'key hash  : {out}/mcu_hash.txt')


if __name__ == '__main__':
    main()
