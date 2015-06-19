
VolDiff: Malware Memory Footprint Analysis
==========================================

VolDiff is a Python script that leverages the [Volatility](https://github.com/volatilityfoundation/volatility) framework to identify malware threats on Windows 7 memory images.

VolDiff can be used to run a collection of Volatility plugins against memory images captured before and after malware execution. It creates a report that highlights system changes based on memory (RAM) analysis.

VolDiff can also be used against a single Windows memory image to automate Volatility plugin execution, and hunt for malicious patterns.

Installation and use directions
--------------------------------
Please refer to the VolDiff [home wiki](https://github.com/aim4r/VolDiff/wiki) for details.

Sample report
--------------
See [this wiki page](https://github.com/aim4r/VolDiff/wiki/Memory-Analysis-of-DarkComet-using-VolDiff) for a sample VolDiff analysis of a system infected with the [DarkComet](https://en.wikipedia.org/wiki/DarkComet) RAT.


Inspiration
------------
This work was initially inspired by Andrew Case ([@attrc](https://twitter.com/attrc)) talk on [analyzing the sophisticated Careto malware sample with memory forensics] (http://2014.video.sector.ca/video/110388398 "analyzing the sophisticated Careto malware sample with memory forensics"). Kudos to [@attrc](https://twitter.com/attrc) and all the Volatility development team for creating and maintaining the greatest memory forensic framework out there!
