#!/bin/sh
set -eu

mkdir -p policy
curl --fail --location --retry 3 \
  -o policy/kev.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl --fail --location --retry 3 \
  -o policy/epss.csv.gz \
  https://epss.cyentia.com/epss_scores-current.csv.gz
mv policy/epss.csv.gz policy/epss.csv
echo "Policy data refreshed. Rebuild the CATS image to package it."
