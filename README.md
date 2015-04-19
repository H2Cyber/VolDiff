Usage: ./VolDiff.sh BASELINE_IMAGE INFECTED_IMAGE PROFILE [OPTION]

Directions:

1. Capture a memory dump of a clean Windows system and save it as "baseline.raw". This image will serve as a baseline for the analysis.

2. Execute your malware sample on the same system, then take a second memory dump and save it as "infected.raw"

3. Run VolDiff as follows: "./VolDiff.sh baseline.raw infected.raw <profile>" where <profile> is Win7SP0x86 or Win7SP1x64 etc

VolDiff will save the output of a selection of volatility plugins for both memory images (baseline and infected), and create a report to highlight changes.

Tested using Volatility 2.4 (vol.py) and Windows 7 images.

Please report bugs to houcem.hachicha[@]gmail.com.
