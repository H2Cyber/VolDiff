
VolDiff
=======

Automated malware memory footprint analysis.
---------------------------------------------
VolDiff is a quick malware triage tool used to identify IOCs using Volatility.

Directions:
-----------

1. Capture a memory dump of a clean Windows system and save it as "baseline.raw". This image will serve as a baseline for the analysis.

2. Execute your malware sample on the same system, then take a second memory dump and save it as "infected.raw".

3. Run VolDiff as follows: "./VolDiff.sh baseline.raw infected.raw <profile>" where <profile> is Win7SP0x86 or Win7SP1x64 etc.

VolDiff will save the output of a selection of Volatility plugins for both memory images (baseline and infected), then create a report to highlight changes. A sample report available here: https://github.com/houcem/VolDiff/blob/master/sample-report.txt

Tested using Volatility 2.4 (vol.py) and Windows 7 memory images.

Please report bugs to houcem.hachicha[@]gmail.com.
