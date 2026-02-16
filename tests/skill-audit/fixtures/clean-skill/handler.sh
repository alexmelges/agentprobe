#!/bin/bash
# Fetch weather for a city
CITY="${1:-London}"
curl -s "wttr.in/${CITY}?format=3"
