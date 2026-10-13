#!/usr/bin/env python3
"""Copy the sensor's factory calibration (OTP) out of the Windows driver data.

    extract_otp.py /mnt/win/ProgramData/Goodix/goodix.dat otp.bin

The Windows driver caches the 64-byte OTP in goodix.dat; it starts with the
marker "NLM1". The Linux driver builds the sensor config and capture DACs
from it.
"""
import os
import sys

OTP_LEN = 64


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    data = open(sys.argv[1], 'rb').read()
    at = data.find(b'NLM1')
    if at < 0 or data.find(b'NLM1', at + 1) >= 0 or at + OTP_LEN > len(data):
        sys.exit(f'{sys.argv[1]}: no unique NLM1 calibration block')
    fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data[at:at + OTP_LEN])
    print(f'OTP copied from offset {at:#x} to {sys.argv[2]}')


if __name__ == '__main__':
    main()
