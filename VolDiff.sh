#!/bin/bash
# VolDiff malware analysis script.
# Written by Houcem Hachicha aka @aim4r.

version="0.9.3"

################################ PRINT VOLDIFF BANNER ################################
echo -e " _    __      ______  _ ________"
echo -e "| |  / /___  / / __ \(_) __/ __/"
echo -e "| | / / __ \/ / / / / / /_/ /_  "
echo -e "| |/ / /_/ / / /_/ / / __/ __/  "
echo -e "|___/\____/_/_____/_/_/ /_/     "

echo -e "\nVolDiff: Malware Memory Footprint Analysis (v$version)"

################################ HELP ################################
if [[ $@ =~ "--help" ]] ; then
  echo -e "\nUsage: ./VolDiff.sh BASELINE_IMAGE INFECTED_IMAGE PROFILE [OPTION]"
  echo -e "\nDirections:"
  echo -e "1. Capture a memory dump of a clean Windows system and save it as \"baseline.raw\". This image will serve as a baseline for the analysis."
  echo -e "2. Execute your malware sample on the same system, then capture a second memory dump and save it as \"infected.raw\""
  echo -e "3. Run VolDiff as follows: \"./VolDiff.sh baseline.raw infected.raw <profile>\" where <profile> is Win7SP0x86 or Win7SP1x64 etc"
  echo -e "VolDiff will save the output of a selection of volatility plugins for both memory images (baseline and infected), then it will create a report to highlight notable changes (new processes, network connections, injected code, suspicious drivers etc)."
  echo -e "\nOptions:"
  echo -e "--help			display this help and exit"
  echo -e "--version		display script version information and exit"
  echo -e "--dependencies		display information about script dependencies and exit"
  echo -e "--process-checks	perform extra process checks to find anomalies and include results in report"
  echo -e "--no-report		do not create a report"
  echo -e "--add-hints		add analysis hints to the report"
  echo -e "\nTested using Volatility 2.4 (vol.py) on Windows 7 images."
  echo -e "Report bugs to houcem.hachicha[@]gmail.com"
  exit
fi

################################ VERSION INFORMATION ################################
if [[ $@ =~ "--version" ]] ; then
  echo -e "This is free software: you are free to change and redistribute it."
  echo -e "There is NO WARRANTY, to the extent permitted by law."
  echo -e "Written by Houcem Hachicha @aim4r. Report bugs to houcem.hachicha[@]gmail.com."
  exit
fi

################################ DEPENDENCIES ################################
if [[ $@ =~ "--dependencies" ]] ; then
  echo -e "Requires volatility 2.4 (vol.py) to be installed."
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
  profile=Win7SP0x86
  echo -e "Profile is not specified. Using default ($profile)..."
elif [[ $3 != Win7SP1x64 ]] &&  [[ $3 != Win7SP0x86 ]] ; then
  profile=$3
  echo -e "WARNING: This script was only tested using Win7SP0x86 and Win7SP1x64 profiles. The specified profile ($profile) seems different!" 
else
  profile=$3
  echo -e "Profile: $profile..."
fi

if [[ $@ =~ "--autoruns" ]] ; then
  echo -e "Adding autoruns to the list of plugins to run..."
fi

################################ CREATING FOLDER TO STRORE OUTPUT ################################
starttime=$(date +%s)
output_dir=VolDiff_$(date +%F_%R)
mkdir $output_dir

################################ DECLARING LIST OF VOLATILITY PLUGINS TO PROCESS ################################
# volatility plugins to run:
declare -a plugins_to_run=("timeliner" "strings" "handles" "psxview" "netscan" "getsids" "pslist" "psscan" "cmdline" "consoles" "dlllist" "svcscan" "mutantscan" "drivermodule" "driverscan" "devicetree" "modscan" "callbacks" "ldrmodules" "privs" "orphanthreads" "malfind" "envars" "idt" "driverirp" "deskscan" "timers" "gditimers" "ssdt")
# volatility plugins to report on (order matters!):
declare -a plugins_to_report=("netscan" "pslist" "psscan" "psxview" "ldrmodules" "dlllist" "malfind" "timeliner" "svcscan" "cmdline" "consoles" "deskscan" "drivermodule" "driverscan" "driverirp" "modscan"  "devicetree" "callbacks" "idt" "orphanthreads" "mutantscan" "getsids" "privs" "gditimers" "ssdt")
# use autoruns plugin if requested:
if [[ $@ =~ "--autoruns" ]] ; then
  plugins_to_run+=("autoruns")
  plugins_to_report+=("autoruns")
fi

################################ RUNING VOLATILITY PLUGINS ################################
echo -e "Running a selection of volatility plugins (CPU intensive)..."
for plugin in "${plugins_to_run[@]}" 
do
  echo -e "Volatility plugin "$plugin" execution in progress..."
  mkdir $output_dir/$plugin
  if [[ $plugin = "mutantscan" ]] || [[ $plugin = "handles" ]] || [[ $plugin = "privs" ]] ; then
    vol.py --profile=$profile -f $baseline_memory_image $plugin --silent &> $output_dir/$plugin/baseline-$plugin.txt &
    vol.py --profile=$profile -f $infected_memory_image $plugin --silent &> $output_dir/$plugin/infected-$plugin.txt &
    wait
  elif [[ $plugin = "orphanthreads" ]]  ; then
    vol.py --profile=$profile -f $baseline_memory_image threads -F OrphanThread &> $output_dir/orphanthreads/baseline-orphanthreads.txt &
    vol.py --profile=$profile -f $infected_memory_image threads -F OrphanThread &> $output_dir/orphanthreads/infected-orphanthreads.txt &
    wait
  # running timeliner in background (time consuming):
  elif [[ $plugin = "timeliner" ]] ; then
    vol.py --profile=$profile -f $baseline_memory_image $plugin &> $output_dir/$plugin/baseline-$plugin.txt &
    vol.py --profile=$profile -f $infected_memory_image $plugin &> $output_dir/$plugin/infected-$plugin.txt &
  elif [[ $plugin = "strings" ]] ; then
    mkdir $output_dir/$plugin/ips-domains
    strings -a -td $baseline_memory_image > $output_dir/$plugin/baseline-$plugin.txt
    strings -a -td $infected_memory_image > $output_dir/$plugin/infected-$plugin.txt
    diff $output_dir/$plugin/baseline-$plugin.txt $output_dir/$plugin/infected-$plugin.txt | grep -E "^>" | sed 's/^..//' &> $output_dir/$plugin/diff-$plugin.txt
    vol.py --profile=$profile -f $infected_memory_image $plugin --string-file=$output_dir/$plugin/diff-$plugin.txt &> $output_dir/$plugin/diff-$plugin-vol.txt
    rm $output_dir/$plugin/baseline-$plugin.txt $output_dir/$plugin/infected-$plugin.txt &> /dev/null
  elif [[ $plugin = "malfind" ]] ; then
    mkdir $output_dir/$plugin/dump-dir-baseline
    mkdir $output_dir/$plugin/dump-dir-infected
    vol.py --profile=$profile -f $baseline_memory_image $plugin -D $output_dir/$plugin/dump-dir-baseline &> $output_dir/$plugin/baseline-$plugin.txt &
    vol.py --profile=$profile -f $infected_memory_image $plugin -D $output_dir/$plugin/dump-dir-infected &> $output_dir/$plugin/infected-$plugin.txt &
    wait
  else
    vol.py --profile=$profile -f $baseline_memory_image $plugin &> $output_dir/$plugin/baseline-$plugin.txt &
    vol.py --profile=$profile -f $infected_memory_image $plugin &> $output_dir/$plugin/infected-$plugin.txt &
    wait
  fi
done
wait

################################ DIFFING VOLATILITY RESULTS ################################
echo -e "Diffing output results..."
for plugin in "${plugins_to_run[@]}"
do
  if [[ $plugin == "strings" ]]; then
    # special processing for strings:
    echo -e "Hunting for IPs, domains and email addresses in memory strings..."
    cat $output_dir/strings/diff-strings-vol.txt | perl -e 'while(<>){if(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/){print $_;}}' &>> $output_dir/strings/ips-domains/diff-ips-domains-vol.txt
    cat $output_dir/strings/diff-strings-vol.txt | perl -e 'while(<>){ if(/(http|https|ftp|mail)\:[\/\w.]+/){print $_;}}' &>> $output_dir/strings/ips-domains/diff-ips-domains-vol.txt
    cat $output_dir/strings/diff-strings-vol.txt | grep -E -o "\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b" &>> $output_dir/strings/ips-domains/diff-ips-domains-vol.txt
  else
    diff $output_dir/$plugin/baseline-$plugin.txt $output_dir/$plugin/infected-$plugin.txt | grep -E "^>" | sed 's/^..//' &> $output_dir/$plugin/diff-$plugin.txt
  fi
done

################################ PROCESS CHECKS ################################
if [[ $@ =~ "--process-checks" ]] ; then
  echo -e "Hunting for anomalies in $infected_memory_image processes..."

  # Verify PID of System process = 4
  cat $output_dir/psscan/infected-psscan.txt | grep " System " | tr -s ' ' | cut -d " " -f 3 > system-pids.tmp
  while read pid; do
    if [[ $pid != "4" ]] ; then
      echo -e "\nSuspicious 'System' process running with PID $pid (expected PID 4)." >> $output_dir/process-checks.tmp
    fi
  done < system-pids.tmp
  rm system-pids.tmp &> /dev/null
 
 # verify only one instance of certain processes is running:
  for process in " services.exe" " System" " wininit.exe" " smss.exe" " lsass.exe" " lsm.exe" " explorer.exe"; do
    if [[ "$(cat $output_dir/psscan/infected-psscan.txt | grep $process | wc -l)" != "1" ]] ; then
      echo -e "\nMultiple instances of$process were detected. Only one instance should exist.\n" >> $output_dir/process-checks.tmp
      sed -n '2p' $output_dir/psscan/infected-psscan.txt >> $output_dir/process-checks.tmp
      sed -n '3p' $output_dir/psscan/infected-psscan.txt >> $output_dir/process-checks.tmp
      cat $output_dir/psscan/infected-psscan.txt | grep $process >> $output_dir/process-checks.tmp
    fi
  done

  # verify that some processes do not have a child:
  for process in "lsass.exe" "lsm.exe"; do
    cat $output_dir/psscan/infected-psscan.txt | grep $process | tr -s ' ' | cut -d " " -f 3 >> pids.tmp
  done
  cat $output_dir/psscan/infected-psscan.txt | tr -s ' ' | cut -d " " -f 4 >> ppids.tmp
  while read pid; do
    while read ppid; do
      if [[ "$pid" == "$ppid" ]]; then
        echo -e "\nProcess with (PID $ppid) is not supposed to be a parent.\n" >> $output_dir/process-checks.tmp
        sed -n '2p' $output_dir/psscan/infected-psscan.txt >> $output_dir/process-checks.tmp
        sed -n '3p' $output_dir/psscan/infected-psscan.txt >> $output_dir/process-checks.tmp
        cat $output_dir/psscan/infected-psscan.txt | grep " $ppid " >> $output_dir/process-checks.tmp
      fi
    done < ppids.tmp
  done < pids.tmp
  rm pids.tmp ppids.tmp &> /dev/null

  # verify child/parent process relationships:
  for child in " svchost.exe" " smss.exe" " conhost.exe" " services.exe" " lsass.exe" " lsm.exe" " dllhost.exe" " taskhost.exe" " spoolsv.exe"; do
    if [[ $child = " svchost.exe" ]] || [[ $child = " dllhost.exe" ]] || [[ $child = " taskhost.exe" ]] || [[ $child = " spoolsv.exe" ]]; then parent=" services.exe"; fi
    if [[ $child = " smss.exe" ]]; then parent=" System"; fi
    if [[ $child = " conhost.exe" ]]; then parent=" csrss.exe"; fi
    if [[ $child = " services.exe" ]] || [[ $child = " lsass.exe" ]] || [[ $child = " lsm.exe" ]]; then parent=" wininit.exe"; fi
    if [[ "$(cat $output_dir/psscan/infected-psscan.txt | grep $parent | wc -l)" = "1" ]] ; then
      cat $output_dir/psscan/infected-psscan.txt | grep $child | tr -s ' ' | cut -d " " -f 4 > child-ppids.tmp
      parent_pid="$(cat $output_dir/psscan/infected-psscan.txt | grep $parent | tr -s ' ' | cut -d ' ' -f 3)"
      while read ppid; do
        ppid=$( printf $ppid )
        parent_pid=$( printf $parent_pid )
        if [[ $ppid != $parent_pid ]] ; then
          echo -e "\nUnexpected parent process for$child ($ppid instead of $parent_pid)" >> $output_dir/process-checks.tmp
        fi
      done < child-ppids.tmp
      rm child-ppids.tmp &> /dev/null
    fi
  done

  # verify processes are running in expected sessions:
  for process in " wininit.exe" " services.exe" " lsass.exe" " svchost.exe" " lsm.exe" " winlogon.exe"; do
    if [[ $process = " csrss.exe" ]] || [[ $process = " wininit.exe" ]] || [[ $process = " services.exe" ]] || [[ $process = " lsass.exe" ]] || [[ $process = " svchost.exe" ]]|| [[ $process = " lsm.exe" ]]; then session="0"; fi
    if [[ $process = " winlogon.exe" ]]; then session="1"; fi
    cat $output_dir/pslist/infected-pslist.txt | grep $process | tr -s ' ' | cut -d ' ' -f 7 > process_sessions.temp
    while read psession; do
      if [[ $psession != $session ]] ; then
        echo -e "\nProcess$process running in unexpected session ($psession instead of $session)\n" >> $output_dir/process-checks.tmp
        sed -n '2p' $output_dir/pslist/infected-pslist.txt >> $output_dir/process-checks.tmp
        sed -n '3p' $output_dir/pslist/infected-pslist.txt >> $output_dir/process-checks.tmp
        cat $output_dir/pslist/infected-pslist.txt | grep $process >> $output_dir/process-checks.tmp
      fi
    done < process_sessions.temp
    rm process_sessions.temp &> /dev/null
  done

  # verify if any processes have suspicious l33t names:
  cat $output_dir/psscan/infected-psscan.txt | grep -E -i "snss|crss|cssrs|csrsss|lass|isass|lssass|lsasss|scvh|svch0st|svhos|svchst|lsn|g0n|l0g|nvcpl|rundii" > suspicious_process.tmp
  if [[ -s suspicious_process.tmp ]]; then
    echo -e "\nProcesses with suspicious names:\n" >> $output_dir/process-checks.tmp
    sed -n '2p' $output_dir/psscan/infected-psscan.txt >> $output_dir/process-checks.tmp
    sed -n '3p' $output_dir/psscan/infected-psscan.txt >> $output_dir/process-checks.tmp
    cat suspicious_process.tmp >> $output_dir/process-checks.tmp
  fi
  rm suspicious_process.tmp &> /dev/null

  # verify if any hacker tools were used:
  cat $output_dir/psscan/infected-psscan.txt | grep -E -i "wmic|powershell|winrm|psexec|net.exe|at.exe|schtasks" > suspicious_tools.tmp
  if [[ -s suspicious_tools.tmp ]]; then
    echo -e "\nSuspicious processes that may have been used for remote execution, lateral movement or privilege escalation:\n" >> $output_dir/process-checks.tmp
    sed -n '2p' $output_dir/psscan/infected-psscan.txt >> $output_dir/process-checks.tmp
    sed -n '3p' $output_dir/psscan/infected-psscan.txt >> $output_dir/process-checks.tmp
    cat suspicious_tools.tmp >> $output_dir/process-checks.tmp
  fi
  rm suspicious_tools.tmp &> /dev/null

  # check process executable path:
  for process in "smss.exe" "crss.exe" "wininit.exe" "services.exe" "lsass.exe" "svchost.exe" "lsm.exe" "explorer.exe" "winlogon"; do
    if [[ $process == "smss.exe" ]]; then processpath="\windows\system32\smss.exe" ; fi
    if [[ $process == "crss.exe" ]]; then processpath="\windows\system32\csrss.exe" ; fi
    if [[ $process == "wininit.exe" ]]; then processpath="\windows\system32\wininit.exe" ; fi
    if [[ $process == "services.exe" ]]; then processpath="\windows\system32\services.exe" ; fi
    if [[ $process == "lsass.exe" ]]; then processpath="\windows\system32\lsass.exe" ; fi
    if [[ $process == "svchost.exe" ]]; then processpath="\windows\system32\svchost.exe" ; fi
    if [[ $process == "lsm.exe" ]]; then processpath="\windows\system32\lsm.exe" ; fi
    if [[ $process == "explorer.exe" ]]; then processpath="\windows\explorer.exe" ; fi
    if [[ $process == "winlogon.exe" ]]; then processpath="\windows\system32\winlogon.exe" ; fi
    cat $output_dir/dlllist/infected-dlllist.txt | grep -i -A 1 $process | grep "Command line" | grep -o '\\.*' | cut -d ' ' -f 1 | tr '[:upper:]' '[:lower:]' | sed 's,\\,\\\\,g' > $output_dir/path_list.temp
    if [[ -s $output_dir/path_list.temp ]]; then
      while read path; do
        if [[ "$path" != "$processpath" ]]; then
          echo -e "\nProcess $process is running from $path instead of $processpath" >> $output_dir/process-checks.tmp
        fi
      done < $output_dir/path_list.temp
    fi
    rm $output_dir/path_list.temp &> /dev/null
  done

  # detect process hollowing
  mkdir $output_dir/hollowing
  mkdir $output_dir/hollowing/procdump
  vol.py --profile=$profile -f $infected_memory_image procdump -u -D $output_dir/hollowing/procdump &> /dev/null
  cat $output_dir/psscan/infected-psscan.txt | tr -s ' ' | cut -d ' ' -f 2 | cut -d '.' -f 1 | sort | uniq > $output_dir/hollowing/process-names.tmp
  tail -n +4 $output_dir/hollowing/process-names.tmp > $output_dir/hollowing/procnames.tmp
  while read process ; do
    cat $output_dir/psscan/infected-psscan.txt | grep -i $process | tr -s ' ' | cut -d ' ' -f 3 > $output_dir/hollowing/$process-pids.tmp
    touch $output_dir/hollowing/$process-size.tmp
    while read pid ; do
      ls -l $output_dir/hollowing/procdump/ | tr -s ' ' | cut -d ' ' -f5,9 | grep -i "executable.$pid.exe" | cut -d ' ' -f 1 >> $output_dir/hollowing/$process-size.tmp
    done < $output_dir/hollowing/$process-pids.tmp
    cat $output_dir/hollowing/$process-size.tmp | uniq > $output_dir/hollowing/$process-size-uniq.tmp
    lines=`wc -l < $output_dir/hollowing/$process-size-uniq.tmp`
    if [[ $lines != 1 ]] && [[ $lines != 0 ]]  ; then 
      echo -e "\nPossible process hollowing detected in $process:\n" >> $output_dir/process-checks.tmp
      echo -e "Process		PID	Size" >> $output_dir/process-checks.tmp
      echo -e "-----------------------------------" >> $output_dir/process-checks.tmp
      while read pid ; do
        echo -e "$process		$pid	`ls -l $output_dir/hollowing/procdump/ | tr -s ' ' | cut -d ' ' -f5,9 | grep -i "executable.$pid.exe" | cut -d ' ' -f 1`" >> $output_dir/process-checks.tmp
      done < $output_dir/hollowing/$process-pids.tmp   
    fi
    rm $output_dir/hollowing/$process-size.tmp $output_dir/hollowing/$process-pids.tmp $output_dir/hollowing/$process-size-uniq.tmp
  done < $output_dir/hollowing/procnames.tmp
  rm $output_dir/hollowing/process-names.tmp $output_dir/hollowing/procnames.tmp &> /dev/null
  rm -r $output_dir/hollowing $output_dir/hollowing/procdump &> /dev/null

fi

################################ REPORT CREATION ################################
if [[ $@ =~ "--no-report" ]] ; then
  endtime=$(date +%s)
  echo -e "\nAll done in $(($endtime - $starttime)) seconds."
  rm $output_dir/process-checks.tmp &> /dev/null
  exit
fi
echo -e "Creating a report..."
report=VolDiff-report.txt
touch $output_dir/$report
echo -e " _    __      ______  _ ________" >> $output_dir/$report
echo -e "| |  / /___  / / __ \(_) __/ __/" >> $output_dir/$report
echo -e "| | / / __ \/ / / / / / /_/ /_  " >> $output_dir/$report
echo -e "| |/ / /_/ / / /_/ / / __/ __/  " >> $output_dir/$report
echo -e "|___/\____/_/_____/_/_/ /_/     " >> $output_dir/$report
echo -e "\nVolatility analysis report generated by VolDiff v$version." >> $output_dir/$report 
echo -e "Download the latest version from https://github.com/aim4r/VolDiff/." >> $output_dir/$report
touch $output_dir/no_new_entries.tmp
for plugin in "${plugins_to_report[@]}"
do
  if [[ -s $output_dir/$plugin/diff-$plugin.txt ]] ; then
     # special processing for psxview:
    if [[ $plugin = "psxview" ]] ; then
      cat $output_dir/psxview/diff-psxview.txt | grep "[0-9] False" > $output_dir/psxview/hidden.tmp
      if [[ -s $output_dir/psxview/hidden.tmp ]] ; then
        echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
        echo -e "===========================================================================\n" >> $output_dir/$report
        sed -n '2p' $output_dir/psxview/infected-psxview.txt >> $output_dir/$report
        sed -n '3p' $output_dir/psxview/infected-psxview.txt >> $output_dir/$report
        cat $output_dir/psxview/hidden.tmp >> $output_dir/$report
        if [[ $@ =~ "--add-hints" ]] ; then
          echo -e "\nHint: psxview enumerates processes in 7 different ways. The output above is filtered to only display processes that were hidden." >> $output_dir/$report
        fi
      else
        echo -e "$plugin" >> $output_dir/no_new_entries.tmp 
      fi
      rm $output_dir/psxview/hidden.tmp &> /dev/null
    # processing pslist and psscan output:
    elif [[ $plugin = "pslist"  ]] || [[ $plugin = "psscan"  ]] ; then
     echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
     echo -e "===========================================================================\n" >> $output_dir/$report
     sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
     sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
     cat $output_dir/$plugin/baseline-$plugin.txt | tr -s ' ' | cut -d " " -f 3 > $output_dir/$plugin/baseline-pids.temp
     cat $output_dir/$plugin/infected-$plugin.txt | tr -s ' ' | cut -d " " -f 3  > $output_dir/$plugin/infected-pids.temp
     diff $output_dir/$plugin/baseline-pids.temp $output_dir/$plugin/infected-pids.temp | grep -E "^>" | sed 's/^..//' | uniq &>> $output_dir/$plugin/unique-new-pids.temp
     while read pid; do
       cat $output_dir/$plugin/infected-$plugin.txt | grep $pid >> $output_dir/$report
     done < $output_dir/$plugin/unique-new-pids.temp
     rm $output_dir/$plugin/baseline-pids.temp $output_dir/$plugin/infected-pids.temp $output_dir/$plugin/unique-new-pids.temp &> /dev/null
    #processing netscan output
    elif [[ $plugin = "netscan"  ]] ; then
      echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
      echo -e "===========================================================================\n" >> $output_dir/$report
      sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
      cat $output_dir/$plugin/diff-$plugin.txt >> $output_dir/$report
    # processing ldrmodules output
    elif [[ $plugin = "ldrmodules"  ]] ; then
      cat $output_dir/$plugin/diff-$plugin.txt | grep "False" | grep -E -v -i "system32|explorer.exe|iexplore.exe" | sort | uniq >> $output_dir/$plugin/$plugin.tmp
      if [[ -s $output_dir/$plugin/$plugin.tmp ]] ; then
        echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
        echo -e "===========================================================================\n" >> $output_dir/$report
        sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
        sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
        cat $output_dir/$plugin/$plugin.tmp >> $output_dir/$report
        if [[ $@ =~ "--add-hints" ]] ; then
          echo -e "\nHint: DLLs are tracked in three different linked lists for each process. ldrmodules queries each list and displays the results for comparison. The output above is filtered to only display DLLs hidden from these lists and stored in uncommon directories." >> $output_dir/$report
        fi
      else
        echo -e "$plugin" >> $output_dir/no_new_entries.tmp 
      fi
      rm $output_dir/$plugin/$plugin.tmp &> /dev/null
    # processing dlllist output:
    elif [[ $plugin = "dlllist"  ]] ; then
      cat $output_dir/$plugin/diff-$plugin.txt | grep "Command line" | grep -E -v -i "system32|explorer.exe|iexplore.exe" | sed -e 's/Command line : //' | sort | uniq > $output_dir/$plugin/execs.tmp
      if [[ -s $output_dir/$plugin/execs.tmp ]] ; then
        echo -e "\n\nSuspicious new executables" >> $output_dir/$report
        echo -e "===========================================================================\n" >> $output_dir/$report
        cat $output_dir/$plugin/execs.tmp >> $output_dir/$report
      fi
      rm $output_dir/$plugin/execs.tmp &> /dev/null
      cat $output_dir/$plugin/diff-$plugin.txt | grep -o -E "C:.*.dll" | grep -v -i "System32" | uniq | sort > $output_dir/$plugin/dlls.tmp
      if [[ -s $output_dir/$plugin/dlls.tmp ]] ; then
        echo -e "\n\nSuspicious new DLLs" >> $output_dir/$report
        echo -e "===========================================================================\n" >> $output_dir/$report
        cat $output_dir/$plugin/dlls.tmp >> $output_dir/$report
      fi
      rm $output_dir/$plugin/execs.tmp &> /dev/null  
    # filtering deskscan output:
    elif [[ $plugin = "deskscan"  ]] ; then
      cat $output_dir/$plugin/diff-$plugin.txt | grep "Desktop:" >> $output_dir/$plugin/$plugin.tmp
      if [[ -s $output_dir/$plugin/$plugin.tmp ]] ; then
        echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
        echo -e "===========================================================================\n" >> $output_dir/$report
        cat $output_dir/$plugin/$plugin.tmp >> $output_dir/$report
        if [[ $@ =~ "--add-hints" ]] ; then
          echo -e "\nHint: Use wintree to view a tree of the windows in suspicious desktops." >> $output_dir/$report
        fi
      else
        echo -e "$plugin" >> $output_dir/no_new_entries.tmp 
      fi
      rm $output_dir/$plugin/$plugin.tmp &> /dev/null
    # filtering timeliner results:
    elif [[ $plugin = "timeliner" ]] ; then
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PROCESS" >> $output_dir/$plugin/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "NETWORK CONNECT" >> $output_dir/$plugin/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PE HEADER (module)" >> $output_dir/$plugin/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PE HEADER (exe)" >> $output_dir/$plugin/$plugin.tmp
     echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
     echo -e "===========================================================================\n" >> $output_dir/$report
     cat $output_dir/$plugin/$plugin.tmp | sort >> $output_dir/$report
     rm $output_dir/$plugin/$plugin.tmp &> /dev/null
    # processing plugins that don't need output formatting:
    elif [[ $plugin = "devicetree" ]] || [[ $plugin = "orphanthreads" ]] || [[ $plugin = "cmdline" ]] || [[ $plugin = "consoles" ]] || [[ $plugin = "svcscan" ]] || [[ $plugin = "driverirp" ]] || [[ $plugin = "malfind" ]] || [[ $plugin = "getsids" ]] || [[ $plugin = "autoruns" ]] ; then
      echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
      echo -e "===========================================================================\n" >> $output_dir/$report
      cat $output_dir/$plugin/diff-$plugin.txt >> $output_dir/$report
    # processing other plugins:
    else
      echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
      echo -e "===========================================================================\n" >> $output_dir/$report
      sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
      sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
      cat $output_dir/$plugin/diff-$plugin.txt >> $output_dir/$report
    fi
    # additional processing for malfind dumped processes
    if [[ $plugin = "malfind" ]] ; then
      strings -a -td $output_dir/malfind/dump-dir-infected/* > $output_dir/malfind/dump-dir-infected/malfind-strings.temp
      cat $output_dir/malfind/dump-dir-infected/malfind-strings.temp | grep -oE '\b(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]' | uniq >> $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp
      cat $output_dir/malfind/dump-dir-infected/malfind-strings.temp | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | uniq >> $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp
      cat $output_dir/malfind/dump-dir-infected/malfind-strings.temp | grep -E -o "\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b" | uniq >> $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp
      if [[ -s $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp ]] ; then
        echo -e "\n\nSuspicious ips/domains/emails found in dumped processes (malfind)" >> $output_dir/$report
        echo -e "===========================================================================\n" >> $output_dir/$report
        cat $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp >> $output_dir/$report
      fi
      rm $output_dir/malfind/dump-dir-infected/infected-ip-domains.temp $output_dir/malfind/dump-dir-infected/malfind-strings.temp &> /dev/null
      if [[ $@ =~ "--add-hints" ]] ; then
        echo -e "\nHint: Suspicious malfind processes were dumped to disk, and can be reversed as normal or uploaded to VT. IPs and domains from the entire memory image were dumped to disk under $output_dir/strings/ips-domains (too verbose to be included here). Use grep -A 10 and -B 10 to investigate strings located next to suspicious ones. Note that strings/diff-strings-vol.txt includes strings and associated PIDs, and thus should be grepped for suspicious PIDs, or strings." >> $output_dir/$report
      fi
    fi
    # adding hints to help in further analysis:
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
      if [[ $plugin = "idt" ]] ; then
        echo -e "\nHint: Look for hooks that point inside anomalous modules. Some interrupts can point inside rootkit code." >> $output_dir/$report
      fi
      if [[ $plugin = "getsids" ]] ; then
        echo -e "\nHint: Check the output of handles for suspicious processes, and grep for mutants, then Google those. Also grep the output of ldrmodules for any hidden dlls associated with suspicious processes. Note that the procexedump and dlldump volatility plugins can be used to respectively dump processes and DLLs from memory to disk." >> $output_dir/$report
      fi
      if [[ $plugin = "timers" ]] ; then
        echo -e "\nHint: Malware can set kernel timers to run functions at specified intervals." >> $output_dir/$report
      fi
      if [[ $plugin = "gditimers" ]] ; then
        echo -e "\nHint: Malware can set timers to run functions at specified intervals." >> $output_dir/$report
      fi
      if [[ $plugin = "mutantscan" ]] ; then
        echo -e "\nHint: Google mutants associated with suspicious processes." >> $output_dir/$report
      fi
      if [[ $plugin = "ssdt" ]] ; then
        echo -e "\nHint: Some rootkits manipulate SSDT entries to hide its files or registry entries from usermode." >> $output_dir/$report
      fi
    fi
  else
    echo -e "$plugin" >> $output_dir/no_new_entries.tmp 
  fi
done

# display list of plugins with no notable changes:
if [[ -s $output_dir/no_new_entries.tmp ]]; then
  echo -e "\n\nNo notable changes to highlight from the following plugins" >> $output_dir/$report
  echo -e "===========================================================================\n" >> $output_dir/$report
  cat $output_dir/no_new_entries.tmp >> $output_dir/$report
fi
rm $output_dir/no_new_entries.tmp &> /dev/null

# add identified process anamalies to the report:
if [[ $@ =~ "--process-checks" ]] ; then
  if [[ -s $output_dir/process-checks.tmp ]]; then
    echo -e "\n\nProcess anomalies (based on $infected_memory_image memory image analysis)" >> $output_dir/$report
    echo -e "===========================================================================" >> $output_dir/$report
    cat $output_dir/process-checks.tmp >> $output_dir/$report
  fi
  rm $output_dir/process-checks.tmp &> /dev/null
fi

echo -e "\n\nEnd of report." >> $output_dir/$report

endtime=$(date +%s)
echo -e "\nAll done in $(($endtime - $starttime)) seconds, report saved to $output_dir/$report."
