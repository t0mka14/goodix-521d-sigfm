/*
 * Sensor config for the Goodix 27c6:521d (GF5298), built from the factory
 * calibration (OTP) the Windows driver keeps in goodix.dat.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <stdint.h>

#define GOODIX521D_OTP_LEN 64
#define GOODIX521D_CONFIG_LEN 256

/* Fill the 256-byte MCU config and the four image DACs from the OTP.
 * Returns 0 on success, -1 if the OTP or template is not as expected. */
int goodix521d_build_config (const uint8_t otp[GOODIX521D_OTP_LEN],
                             uint8_t       config[GOODIX521D_CONFIG_LEN],
                             uint16_t      dacs[4]);
