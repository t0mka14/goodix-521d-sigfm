/*
 * SIGFM matcher for the Goodix 27c6:521d (GF5298), see sigfm.h.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "sigfm.h"

#include <algorithm>
#include <cmath>
#include <set>
#include <utility>
#include <vector>

#include <opencv2/core.hpp>
#include <opencv2/features2d.hpp>
#include <opencv2/imgproc.hpp>

#define MIN_MATCH 5
#define DISTANCE_MATCH 0.75
#define LENGTH_MATCH 0.05
#define ANGLE_MATCH 0.05
#define BOX_RADIUS 5
#define CONTRAST 45.0

struct _SigfmFeatures
{
  std::vector<cv::KeyPoint> keypoints;
  cv::Mat                   descriptors;
};

void
sigfm_median (const uint16_t *const *frames, int n, uint16_t *out)
{
  std::vector<uint16_t> v (n);

  for (int i = 0; i < SIGFM_PIXELS; i++)
    {
      for (int k = 0; k < n; k++)
        v[k] = frames[k][i];
      std::sort (v.begin (), v.end ());
      out[i] = (n % 2) ? v[n / 2] :
               (uint16_t) ((v[n / 2 - 1] + v[n / 2] + 1) / 2);
    }
}

void
sigfm_prepare (const uint16_t *background, const uint16_t *frame,
               uint8_t *out)
{
  cv::Mat x (SIGFM_HEIGHT, SIGFM_WIDTH, CV_64F);
  cv::Mat mean;
  cv::Scalar m, sd;

  for (int i = 0; i < SIGFM_PIXELS; i++)
    x.at<double> (i) = (double) background[i] - (double) frame[i];

  /* Remove what is left of the background's low frequencies. */
  cv::blur (x, mean, cv::Size (2 * BOX_RADIUS + 1, 2 * BOX_RADIUS + 1),
            cv::Point (-1, -1), cv::BORDER_REFLECT_101);
  x -= mean;

  cv::meanStdDev (x, m, sd);
  for (int i = 0; i < SIGFM_PIXELS; i++)
    {
      double v = 128.0 + x.at<double> (i) / (sd[0] + 1e-9) * CONTRAST;
      out[i] = (uint8_t) std::clamp (v, 0.0, 255.0);
    }
}

SigfmFeatures *
sigfm_extract (const uint8_t *image)
{
  SigfmFeatures *f = new SigfmFeatures ();
  cv::Mat img (SIGFM_HEIGHT, SIGFM_WIDTH, CV_8U, (void *) image);

  cv::SIFT::create ()->detectAndCompute (img, cv::noArray (),
                                         f->keypoints, f->descriptors);
  return f;
}

int
sigfm_keypoints (const SigfmFeatures *features)
{
  return (int) features->keypoints.size ();
}

void
sigfm_free (SigfmFeatures *features)
{
  delete features;
}

static bool
close_enough (double a, double b)
{
  a = std::fabs (a);
  b = std::fabs (b);
  if (a == 0 || b == 0)
    return a == b;
  return 1 - std::min (a, b) / std::max (a, b) <= ANGLE_MATCH;
}

int
sigfm_score (const SigfmFeatures *a, const SigfmFeatures *b, int max_count)
{
  typedef std::pair<double, double> Pt;
  std::vector<std::vector<cv::DMatch>> knn;
  std::set<std::pair<Pt, Pt>> unique;
  std::vector<std::pair<double, double>> angles;
  std::vector<std::pair<Pt, Pt>> m;
  size_t ratio_matches = 0;
  int count = 0;

  if (a->keypoints.size () < MIN_MATCH || b->keypoints.size () < MIN_MATCH)
    return 0;

  cv::BFMatcher ().knnMatch (a->descriptors, b->descriptors, knn, 2);
  for (const auto &p : knn)
    {
      if (p.size () != 2 || !(p[0].distance < DISTANCE_MATCH * p[1].distance))
        continue;
      const cv::Point2f &p1 = a->keypoints[p[0].queryIdx].pt;
      const cv::Point2f &p2 = b->keypoints[p[0].trainIdx].pt;
      /* Matches are compared on whole pixels, rounding half to even. */
      unique.insert ({ { std::nearbyint (p1.x), std::nearbyint (p1.y) },
                       { std::nearbyint (p2.x), std::nearbyint (p2.y) } });
      ratio_matches++;
    }
  if (ratio_matches < MIN_MATCH)
    return 0;
  m.assign (unique.begin (), unique.end ());

  for (size_t j = 0; j < m.size (); j++)
    for (size_t k = j + 1; k < m.size (); k++)
      {
        double v1x = m[j].first.first - m[k].first.first;
        double v1y = m[j].first.second - m[k].first.second;
        double v2x = m[j].second.first - m[k].second.first;
        double v2y = m[j].second.second - m[k].second.second;
        double l1 = std::hypot (v1x, v1y), l2 = std::hypot (v2x, v2y);

        if (l1 < 1e-6 || l2 < 1e-6)
          continue;
        if (1 - std::min (l1, l2) / std::max (l1, l2) > LENGTH_MATCH)
          continue;
        double prod = l1 * l2;
        angles.push_back ({ std::clamp ((v1x * v2y - v1y * v2x) / prod, -1.0, 1.0),
                            std::clamp ((v1x * v2x + v1y * v2y) / prod, -1.0, 1.0) });
      }

  for (size_t j = 0; j < angles.size (); j++)
    for (size_t k = j + 1; k < angles.size (); k++)
      if (close_enough (angles[j].first, angles[k].first) &&
          close_enough (angles[j].second, angles[k].second))
        if (++count >= max_count)
          return count;

  return count;
}
