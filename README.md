
VolDiff: Malware Memory Footprint Analysis
==========================================

VolDiff is a Python script that leverages the [Volatility](https://github.com/volatilityfoundation/volatility) framework to identify malware threats on Windows 7 memory images.

VolDiff can be used to run a collection of Volatility plugins against memory images captured before and after malware execution. It creates a report that highlights system changes based on memory (RAM) analysis.

VolDiff can also be used against a single Windows memory image to automate Volatility plugin execution, and hunt for malicious patterns.

Use Directions
----------------

If a malware sample is available (such as a malicious executable, a PDF or MS Office file), then VolDiff can be used to highlight the system changes introduced by the sample:

1. Capture a memory dump of a clean Windows system and save it as "baseline.vmem". This image will serve as a baseline for the analysis.

2. Execute the malware sample on the same system (usual [precautions](https://zeltser.com/vmware-network-isolation-for-malware-analysis/) apply), then capture a second memory dump and save it as "infected.vmem".

3. Run VolDiff.py using the following options:

`python VolDiff.py path/to/baseline.vmem path/to/infected.vmem profile --malware-checks`

`profile` should be `Win7SP0x86` or `Win7SP1x64` etc.

The `--malware-checks` option instructs VolDiff to perform a number of checks such as process parent/child relationships, unusual loaded DLLs, suspicious imports, malicious drivers and much more. VolDiff will save the output of a selection of Volatility plugins for the memory images, then it will create a report to highlight any identified indicators of compromise. 

If a single memory image of an potentially infected system is available, use the following command to analyse it using VolDiff:

`python VolDiff.py path/to/image.vmem profile --malware-checks`

Please refer to the VolDiff [wiki pages](https://github.com/aim4r/VolDiff/wiki) for more details.
