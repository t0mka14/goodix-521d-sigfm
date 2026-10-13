/*
 * SIGFM matcher for the Goodix 27c6:521d (GF5298) press sensor.
 *
 * SIFT keypoints, Lowe ratio test, then a geometric consistency count
 * (pairs of matches whose relative distance and angle agree), after
 * https://github.com/goodix-fp-linux-dev/sigfm. The 64x80 sensor is too
 * small for minutiae (NBIS), but SIFT finds enough ridge texture.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIGFM_WIDTH 64
#define SIGFM_HEIGHT 80
#define SIGFM_PIXELS (SIGFM_WIDTH * SIGFM_HEIGHT)

typedef struct _SigfmFeatures SigfmFeatures;

/* Per-pixel median of n raw 12-bit frames (the sensor's background). */
void sigfm_median (const uint16_t *const *frames, int n, uint16_t *out);

/* Matcher image: (background - frame), local mean removed, contrast
 * normalised to 8 bits. */
void sigfm_prepare (const uint16_t *background, const uint16_t *frame,
                    uint8_t *out);

/* SIFT features of a prepared image; never NULL. */
SigfmFeatures *sigfm_extract (const uint8_t *image);
int sigfm_keypoints (const SigfmFeatures *features);
void sigfm_free (SigfmFeatures *features);

/* Number of geometrically consistent match pairs (0 = no match),
 * saturating at max_count. */
int sigfm_score (const SigfmFeatures *a, const SigfmFeatures *b,
                 int max_count);

#ifdef __cplusplus
}
#endif
