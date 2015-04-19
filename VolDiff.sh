#!/bin/bash
# VolDiff malware analysis script.
# Written by Houcem Hachicha aka @aim4r.

version="0.9.1"
echo -e "VolDiff v$version"

################################ HELP SECTION ################################
if [[ $@ =~ "--help" ]] ; then
  echo -e "Usage: ./VolDiff.sh BASELINE_IMAGE INFECTED_IMAGE PROFILE [OPTION]"
  echo -e "\nDirections:" 
  echo -e "1. Capture a memory dump of a clean Windows system and save it as \"baseline.raw\". This image will serve as a baseline for the analysis."
  echo -e "2. Execute your malware sample on the same system, then take a second memory dump and save it as \"infected.raw\""
  echo -e "3. Run VolDiff as follows: \"./VolDiff.sh baseline.raw infected.raw <profile>\" where <profile> is Win7SP0x86 or Win7SP1x64 etc"
  echo -e "VolDiff will save the output of a selection of volatility plugins for both memory images (baseline and infected), and create a report to highlight changes."
  echo -e "\nTested using Volatility 2.4 (vol.py) on Windows 7 images."
  echo -e "\n--dependencies	display information about script dependencies and exit"
  echo -e "--help		display this help and exit"
  echo -e "--add-hints	add useful hints to the report"
  echo -e "--no-report	do not create a report"
  echo -e "--version	display script version information and exit"
  echo -e "\nReport bugs (and share ideas) to houcem.hachicha[@]gmail.com"
  exit
fi

################################ VERSION INFORMATION SECTION ################################
if [[ $@ =~ "--version" ]] ; then
  echo -e "This is free software: you are free to change and redistribute it."
  echo -e "There is NO WARRANTY, to the extent permitted by law."
  echo -e "Written by Houcem Hachicha aka @aim4r."
  exit
fi

################################ DEPENDENCIES SECTION ################################
if [[ $@ =~ "--dependencies" ]] ; then
  echo -e "Dependencies:" 
  echo -e "- volatility 2.4 (vol.py) - https://github.com/volatilityfoundation/volatility"
  exit
fi

################################ SETTING PROFILE AND FINDING PATH TO MEMORY IMAGES ################################

if [[ -f $1 ]] ; then
  baseline_memory_image=$1
  echo -e "Path to baseline memory image: $baseline_memory_image..."
elif [[ -f baseline.raw ]] ; then
  baseline_memory_image=baseline.raw
  echo -e "Path to baseline memory image is not valid or was not specified. Using default ($baseline_memory_image)..."
elif [[ -f baseline.vmem ]] ; then
  baseline_memory_image=baseline.vmem
  echo -e "Path to baseline memory image is not valid or was not specified. Using default ($baseline_memory_image)..."
else
  echo -e "Please specify a path to a baseline memory image."
  exit
fi

if [[ -f $2 ]]; then
  infected_memory_image=$2
  echo -e "Path to infected memory image: $infected_memory_image..."
elif [[ -f infected.raw ]] ; then
  infected_memory_image=infected.raw
  echo -e "Path to infected memory image is not valid or was not specified. Using default ($infected_memory_image)..."
elif [[ -f infected.vmem ]] ; then
  infected_memory_image=infected.vmem
  echo -e "Path to infected memory image is not valid or was not specified. Using default ($infected_memory_image)..."
else
  echo -e "Please specify a path to a memory image of an infected system."
  exit
fi

if [[ -z $3 ]] ; then
  #profile=Win7SP1x64
  profile=Win7SP0x86
  echo -e "Profile is not specified. Using default ($profile)..." 
elif [[ $3 != Win7SP1x64 ]] &&  [[ $3 != Win7SP0x86 ]] ; then
  profile=$3
  echo -e "WARNING: This script was only tested using Win7SP0x86 and Win7SP1x64 profiles. The specified profile ($profile) seems different!" 
else
  profile=$3
  echo -e "Profile: $profile..."
fi

################################ CREATING REPORT FOLDERS ################################
starttime=$(date +%s)
output_dir=VolDiff_$(date +%F_%R)
report=VolDiff-report.txt
mkdir $output_dir

################################ RUNING VOLATILITY PLUGINS ################################
echo -e "Running a selection of volatility plugins..."
for plugin in timeliner strings handles psxview netscan getsids pslist psscan cmdline consoles dlllist svcscan mutantscan drivermodule driverscan devicetree modscan callbacks ldrmodules privs orphanthreads malfind  
do
  echo -e "Volatility plugin "$plugin" execution in progress..."
  mkdir $output_dir/$plugin
  if [[ $plugin = "mutantscan" ]] || [[ $plugin = "handles" ]] || [[ $plugin = "privs" ]] ; then
    vol.py --profile=$profile -f $baseline_memory_image $plugin --silent &> $output_dir/$plugin/baseline-$plugin.txt
    vol.py --profile=$profile -f $infected_memory_image $plugin --silent &> $output_dir/$plugin/infected-$plugin.txt 
  elif [[ $plugin = "orphanthreads" ]]  ; then
    vol.py --profile=$profile -f $baseline_memory_image threads -F OrphanThread &> $output_dir/orphanthreads/baseline-orphanthreads.txt
    vol.py --profile=$profile -f $infected_memory_image threads -F OrphanThread &> $output_dir/orphanthreads/infected-orphanthreads.txt
  # running timeliner in background (time consuming)
  elif [[ $plugin = "timeliner" ]] ; then
    vol.py --profile=$profile -f $baseline_memory_image $plugin &> $output_dir/$plugin/baseline-$plugin.txt &
    vol.py --profile=$profile -f $infected_memory_image $plugin &> $output_dir/$plugin/infected-$plugin.txt &
  elif [[ $plugin = "strings" ]] ; then
    mkdir $output_dir/$plugin/ips-domains
    strings -a -td $baseline_memory_image > $output_dir/$plugin/baseline-$plugin.txt 
    strings -a -td $infected_memory_image > $output_dir/$plugin/infected-$plugin.txt
    diff $output_dir/$plugin/baseline-$plugin.txt $output_dir/$plugin/infected-$plugin.txt | grep -E "^>" | sed 's/^..//' &> $output_dir/$plugin/diff-$plugin.txt
    vol.py --profile=$profile -f $infected_memory_image $plugin --string-file=$output_dir/$plugin/diff-$plugin.txt &> $output_dir/$plugin/diff-$plugin-vol.txt
    rm $output_dir/$plugin/baseline-$plugin.txt $output_dir/$plugin/infected-$plugin.txt
  elif [[ $plugin = "malfind" ]] ; then
    mkdir $output_dir/$plugin/dump-dir-baseline
    mkdir $output_dir/$plugin/dump-dir-infected
    vol.py --profile=$profile -f $baseline_memory_image $plugin -D $output_dir/$plugin/dump-dir-baseline &> $output_dir/$plugin/baseline-$plugin.txt
    vol.py --profile=$profile -f $infected_memory_image $plugin -D $output_dir/$plugin/dump-dir-infected &> $output_dir/$plugin/infected-$plugin.txt
  else
    vol.py --profile=$profile -f $baseline_memory_image $plugin &> $output_dir/$plugin/baseline-$plugin.txt
    vol.py --profile=$profile -f $infected_memory_image $plugin &> $output_dir/$plugin/infected-$plugin.txt
  fi
done
wait

################################ DIFFING VOLATILITY RESULTS ################################
echo -e "Diffing output results..."
for plugin in timeliner psxview netscan getsids pslist psscan cmdline consoles dlllist handles svcscan mutantscan drivermodule driverscan devicetree callbacks ldrmodules privs orphanthreads malfind
do
  diff $output_dir/$plugin/baseline-$plugin.txt $output_dir/$plugin/infected-$plugin.txt | grep -E "^>" | sed 's/^..//' &> $output_dir/$plugin/diff-$plugin.txt
done

################################ STRINGS ANALYSIS ################################
echo -e "Hunting for IPs, domains and email addresses in memory strings..."
cat $output_dir/strings/diff-strings-vol.txt | perl -e 'while(<>){if(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/){print $_;}}' &>> $output_dir/strings/ips-domains/diff-ips-domains-vol.txt
cat $output_dir/strings/diff-strings-vol.txt | perl -e 'while(<>){ if(/(http|https|ftp|mail)\:[\/\w.]+/){print $_;}}' &>> $output_dir/strings/ips-domains/diff-ips-domains-vol.txt
cat $output_dir/strings/diff-strings-vol.txt | grep -E -o "\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b" &>> $output_dir/strings/ips-domains/diff-ips-domains-vol.txt


################################ REPORT CREATION ################################
if [[ $@ =~ "--no-report" ]] ; then 
  endtime=$(date +%s)
  echo -e "\nAll done in $(($endtime - $starttime)) seconds. No report created." 
  exit
fi
echo -e "Creating a report..."
touch $output_dir/$report
echo -e " _    __      ______  _ ________" >> $output_dir/$report
echo -e "| |  / /___  / / __ \(_) __/ __/" >> $output_dir/$report
echo -e "| | / / __ \/ / / / / / /_/ /_  " >> $output_dir/$report
echo -e "| |/ / /_/ / / /_/ / / __/ __/  " >> $output_dir/$report
echo -e "|___/\____/_/_____/_/_/ /_/     " >> $output_dir/$report
echo -e "\nVolatility analysis report generated by VolDiff v$version (https://github.com/aim4r/VolDiff/)." >> $output_dir/$report
echo -e "Report bugs to houcem.hachicha[@]gmail.com." >> $output_dir/$report
    
for plugin in netscan pslist psscan psxview ldrmodules malfind timeliner svcscan cmdline consoles drivermodule driverscan modscan callbacks orphanthreads devicetree mutantscan getsids privs
do
  echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
  echo -e "=========================================================================\n" >> $output_dir/$report
  if [[ -s $output_dir/$plugin/diff-$plugin.txt ]] ; then
     # special processing for psxview
    if [[ $plugin = "psxview" ]] ; then
      cat $output_dir/psxview/diff-psxview.txt | grep "[0-9] False" > $output_dir/psxview/hidden.tmp
      if [[ -s $output_dir/psxview/hidden.tmp ]] ; then
        sed -n '2p' $output_dir/psxview/infected-psxview.txt >> $output_dir/$report
        sed -n '3p' $output_dir/psxview/infected-psxview.txt >> $output_dir/$report
        cat $output_dir/psxview/hidden.tmp >> $output_dir/$report
      else
        echo "None" >> $output_dir/$report
      fi
      rm $output_dir/psxview/hidden.tmp
    # processing pslist and psscan output
    elif [[ $plugin = "pslist"  ]] || [[ $plugin = "psscan"  ]] ; then
     sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
     sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
     cat $output_dir/$plugin/baseline-$plugin.txt | tr -s ' ' | cut -d " " -f 3 > $output_dir/$plugin/baseline-pids.temp
     cat $output_dir/$plugin/infected-$plugin.txt | tr -s ' ' | cut -d " " -f 3  > $output_dir/$plugin/infected-pids.temp
     diff $output_dir/$plugin/baseline-pids.temp $output_dir/$plugin/infected-pids.temp | grep -E "^>" | sed 's/^..//' | uniq &>> $output_dir/$plugin/unique-new-pids.temp
     while read pid; do
       cat $output_dir/$plugin/infected-$plugin.txt | grep $pid >> $output_dir/$report
     done < $output_dir/$plugin/unique-new-pids.temp
     rm $output_dir/$plugin/baseline-pids.temp $output_dir/$plugin/infected-pids.temp $output_dir/$plugin/unique-new-pids.temp  
    # processing ldrmodules output
    elif [[ $plugin = "ldrmodules"  ]] ; then
      cat $output_dir/$plugin/diff-$plugin.txt | grep "False" >> $output_dir/$plugin/$plugin.tmp
      if [[ -s $output_dir/$plugin/ldrmodules.tmp ]] ; then
        sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
        sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
        cat $output_dir/$plugin/$plugin.tmp >> $output_dir/$report  
      else
        echo "None" >> $output_dir/$report
      fi
      rm $output_dir/$plugin/$plugin.tmp
    # filtering timeliner results
    elif [[ $plugin = "timeliner" ]] ; then 
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PROCESS" >> $output_dir/$plugin/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "NETWORK CONNECT" >> $output_dir/$plugin/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PE HEADER (module)" >> $output_dir/$plugin/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PE HEADER (exe)" >> $output_dir/$plugin/$plugin.tmp
     cat $output_dir/$plugin/$plugin.tmp | sort >> $output_dir/$report
     rm $output_dir/$plugin/$plugin.tmp
    # processing plugins that don't need output formatting
    elif [[ $plugin = "devicetree" ]] || [[ $plugin = "orphanthreads" ]] || [[ $plugin = "cmdline" ]] || [[ $plugin = "consoles" ]] || [[ $plugin = "svcscan" ]] || [[ $plugin = "malfind" ]] || [[ $plugin = "getsids" ]] ; then
      cat $output_dir/$plugin/diff-$plugin.txt >> $output_dir/$report
    # processing other plugins
    else
      sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
      sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
      cat $output_dir/$plugin/diff-$plugin.txt >> $output_dir/$report
    fi
    # additional processing for malfind dumped processes 
    if [[ $plugin = "malfind" ]] ; then      
      echo -e "\n\nSuspicious ips/domains/emails found in dumped processes (malfind)" >> $output_dir/$report
      echo -e "=========================================================================\n" >> $output_dir/$report
      strings -a -td $output_dir/malfind/dump-dir-infected/* > $output_dir/malfind/dump-dir-infected/malfind-strings.temp 
      cat $output_dir/malfind/dump-dir-infected/malfind-strings.temp | grep -oE '\b(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]' | uniq >> $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp
      cat $output_dir/malfind/dump-dir-infected/malfind-strings.temp | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | uniq >> $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp
      cat $output_dir/malfind/dump-dir-infected/malfind-strings.temp | grep -E -o "\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b" | uniq >> $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp
      if [[ -s $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp ]] ; then
        cat $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp >> $output_dir/$report  
      else
        echo "None" >> $output_dir/$report
      fi
      rm $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp $output_dir/malfind/dump-dir-infected/malfind-strings.temp
    fi
    # adding comments (help for further analysis)
    if [[ $@ =~ "--add-hints" ]] ; then 
      if [[ $plugin = "drivermodule" ]] ; then 
        echo -e "\nHint: Drivers without a module (UNKNOWN) should be considered as suspicious. Use moddump -b to dump suspicious drivers from memory to disk." >> $output_dir/$report
      fi
      if [[ $plugin = "driverscan" ]] ; then 
        echo -e "\nHint: Drivers that have no associated service should be considered as suspicious. Use moddump -b to dump suspicious drivers from memory to disk." >> $output_dir/$report
      fi
      if [[ $plugin = "netscan" ]] ; then 
        echo -e "\nHint: Translate suspicious IPs to domains using Google/VirusTotal, and search for the domains in memory strings." >> $output_dir/$report
      fi
      if [[ $plugin = "privs" ]] ; then 
        echo -e "\nHint: privs was run with the -s switch. It will only show the privileges that were not enabled by default." >> $output_dir/$report
      fi
      if [[ $plugin = "malfind" ]] ; then
        echo -e "\nHint: Suspicious malfind processes were dumped to disk, and can be reversed as normal or uploaded to VT. IPs and domains from the entire memory image were dumped to disk under $output_dir/strings/ips-domains (too verbose to be included here). Use grep -A 10 and -B 10 to investigate strings located next to suspicious ones." >> $output_dir/$report
      fi
      if [[ $plugin = "getsids" ]] ; then 
        echo -e "\nHint: Check the output of handles for suspicious processes, and grep for mutants, then Google those. Also grep the output of ldrmodules for any hidden dlls associated with suspicious processes. Note that the procexedump and dlldump volatility plugins can be used to respectively dump processes and DLLs from memory to disk." >> $output_dir/$report
      fi
      if [[ $plugin = "mutantscan" ]] ; then 
        echo -e "\nHint: Google mutants associated with suspicious processes." >> $output_dir/$report
      fi
    fi
  else
    echo "None" >> $output_dir/$report
  fi
done
echo -e "\nEnd of report." >> $output_dir/$report
endtime=$(date +%s)
echo -e "\nAll done in $(($endtime - $starttime)) seconds, report saved to $output_dir/$report."