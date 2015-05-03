#!/bin/bash
# VolDiff malware analysis script.
# Written by Houcem Hachicha aka @aim4r.

version="0.9.5"

################################ PRINT VOLDIFF BANNER ################################
echo -e " _    __      ______  _ ________"
echo -e "| |  / /___  / / __ \(_) __/ __/"
echo -e "| | / / __ \/ / / / / / /_/ /_  "
echo -e "| |/ / /_/ / / /_/ / / __/ __/  "
echo -e "|___/\____/_/_____/_/_/ /_/     "

echo -e "\nVolDiff: Malware Memory Footprint Analysis (v$version)"

################################ HELP ################################
if [[ $@ =~ "--help" ]] ; then
  echo -e "\nUsage: ./VolDiff.sh BASELINE_IMAGE INFECTED_IMAGE PROFILE [OPTIONS]"
  echo -e "\nDirections:"
  echo -e "1. Capture a memory dump of a clean Windows system and save it as \"baseline.raw\". This image will serve as a baseline for the analysis."
  echo -e "2. Execute your malware sample on the same system, then capture a second memory dump and save it as \"infected.raw\""
  echo -e "3. Run VolDiff as follows: \"./VolDiff.sh baseline.raw infected.raw <profile>\" where <profile> is Win7SP0x86 or Win7SP1x64 etc"
  echo -e "VolDiff will save the output of a selection of volatility plugins for both memory images (baseline and infected), then it will create a report to highlight notable changes (new processes, network connections, injected code, suspicious drivers etc)."
  echo -e "\nOptions:"
  echo -e "--help			display this help and exit"
  echo -e "--version		display script version information and exit"
  echo -e "--dependencies		display information about script dependencies and exit"
  echo -e "--process-checks	find process anomalies (slow)"
  echo -e "--registry-checks	checks for changes in some registry keys (slow)"
  echo -e "--string-checks		searches for suspicious keywords in memory strings (slow)"
  echo -e "--no-report		do not create a report"
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
mkdir $output_dir/tmpfolder

################################ DECLARING LIST OF VOLATILITY PLUGINS TO PROCESS ################################
# volatility plugins to run:
declare -a plugins_to_run=("timeliner" "handles" "psxview" "netscan" "getsids" "pslist" "psscan" "cmdline" "consoles" "dlllist" "svcscan" "mutantscan" "drivermodule" "driverscan" "devicetree" "modscan" "callbacks" "ldrmodules" "privs" "orphanthreads" "malfind" "idt" "driverirp" "deskscan" "timers" "gditimers" "ssdt")

# volatility plugins to report on (order matters!):
declare -a plugins_to_report=("netscan" "pslist" "psscan" "psxview" "malfind" "timeliner" "svcscan" "cmdline" "consoles" "deskscan" "drivermodule" "driverscan" "driverirp" "modscan"  "devicetree" "callbacks" "idt" "orphanthreads" "mutantscan" "getsids" "privs" "timers" "gditimers" "ssdt")

# use autoruns plugin if requested:
if [[ $@ =~ "--autoruns" ]] ; then
  plugins_to_run+=("autoruns")
  plugins_to_report+=("autoruns")
fi

################################ RUNING VOLATILITY PLUGINS ################################
echo -e "Running a selection of volatility plugins (time consuming)..."
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
  diff $output_dir/$plugin/baseline-$plugin.txt $output_dir/$plugin/infected-$plugin.txt | grep -E "^>" | sed 's/^..//' &> $output_dir/$plugin/diff-$plugin.txt
done

################################ PROCESS CHECKS ################################
if [[ $@ =~ "--process-checks" ]] ; then
  echo -e "Hunting for anomalies in $infected_memory_image processes..."
  # declare list of anomalies
  hacker_process_regex="'wmic|powershell|winrm|psexec|net.exe|at.exe|schtasks'"
  hacker_dll_regex="'mimilib.dll|sekurlsa.dll|wceaux.dll|iamdll.dll'"
 
  # verify PID of System process = 4
  cat $output_dir/psscan/infected-psscan.txt | grep " System " | tr -s ' ' | cut -d " " -f 3 > $output_dir/tmpfolder/system-pids.tmp
  while read pid; do
    if [[ $pid != "4" ]] ; then
      echo -e "\nSuspicious 'System' process running with PID $pid (expected PID 4)." >> $output_dir/tmpfolder/process-checks.tmp
    fi
  done < $output_dir/tmpfolder/system-pids.tmp

 # verify only one instance of certain processes is running:
  for process in " services.exe" " System" " wininit.exe" " smss.exe" " lsass.exe" " lsm.exe" " explorer.exe"; do
    if [[ "$(cat $output_dir/psscan/infected-psscan.txt | grep $process | wc -l)" != "1" ]] ; then
      echo -e "\nMultiple instances of$process were detected. Only one instance should exist:" >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '2p' $output_dir/psscan/infected-psscan.txt >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '3p' $output_dir/psscan/infected-psscan.txt >> $output_dir/tmpfolder/process-checks.tmp
      cat $output_dir/psscan/infected-psscan.txt | grep $process >> $output_dir/tmpfolder/process-checks.tmp
    fi
  done

  # verify that some processes do not have a child:
  for process in "lsass.exe" "lsm.exe"; do
    cat $output_dir/psscan/infected-psscan.txt | grep $process | tr -s ' ' | cut -d " " -f 3 >> $output_dir/tmpfolder/cpids.tmp
  done
  cat $output_dir/psscan/infected-psscan.txt | tr -s ' ' | cut -d " " -f 4 >> $output_dir/tmpfolder/ppids.tmp
  while read pid; do
    while read ppid; do
      if [[ "$pid" == "$ppid" ]]; then
        echo -e "\nProcess with (PID $ppid) is not supposed to be a parent:" >> $output_dir/tmpfolder/process-checks.tmp
        sed -n '2p' $output_dir/psscan/infected-psscan.txt >> $output_dir/tmpfolder/process-checks.tmp
        sed -n '3p' $output_dir/psscan/infected-psscan.txt >> $output_dir/tmpfolder/process-checks.tmp
        cat $output_dir/psscan/infected-psscan.txt | grep " $ppid " >> $output_dir/tmpfolder/process-checks.tmp
      fi
    done < $output_dir/tmpfolder/ppids.tmp
  done < $output_dir/tmpfolder/cpids.tmp

  # verify child/parent process relationships:
  for child in " svchost.exe" " smss.exe" " conhost.exe" " services.exe" " lsass.exe" " lsm.exe" " dllhost.exe" " taskhost.exe" " spoolsv.exe"; do
    if [[ $child = " svchost.exe" ]] || [[ $child = " dllhost.exe" ]] || [[ $child = " taskhost.exe" ]] || [[ $child = " spoolsv.exe" ]]; then parent=" services.exe"; fi
    if [[ $child = " smss.exe" ]]; then parent=" System"; fi
    if [[ $child = " conhost.exe" ]]; then parent=" csrss.exe"; fi
    if [[ $child = " services.exe" ]] || [[ $child = " lsass.exe" ]] || [[ $child = " lsm.exe" ]]; then parent=" wininit.exe"; fi
    if [[ "$(cat $output_dir/psscan/infected-psscan.txt | grep $parent | wc -l)" = "1" ]] ; then
      cat $output_dir/psscan/infected-psscan.txt | grep $child | tr -s ' ' | cut -d " " -f 4 > $output_dir/tmpfolder/child-ppids.tmp
      parent_pid="$(cat $output_dir/psscan/infected-psscan.txt | grep $parent | tr -s ' ' | cut -d ' ' -f 3)"
      while read ppid; do
        ppid=$( printf $ppid )
        parent_pid=$( printf $parent_pid )
        if [[ $ppid != $parent_pid ]] ; then
          tail -n +4 $output_dir/psscan/infected-psscan.txt | tr -s ' ' | cut -d ' ' -f 2-3 | grep -i " "$ppid | cut -d ' ' -f 1 | sort | uniq > $output_dir/tmpfolder/ppidprocess.tmp
          if [[ -s $output_dir/tmpfolder/ppidprocess.tmp ]] ; then   
            ppidlines=`cat $output_dir/tmpfolder/ppidprocess.tmp | wc -l`  &> /dev/null
            if [[ $ppidlines = 1 ]] ; then
              echo -e "\nUnexpected parent process for$child: PPID $ppid (`cat $output_dir/tmpfolder/ppidprocess.tmp`) instead of PPID $parent_pid ($parent )." >> $output_dir/tmpfolder/process-checks.tmp
            else
              cat $output_dir/tmpfolder/ppidprocess.tmp | tr '\n' ' ' > $output_dir/tmpfolder/ppparents.tmp
              echo -e "\nUnexpected parent process for$child: PPID $ppid ( multiple associated processes: `cat $output_dir/tmpfolder/ppparents.tmp`) instead of PPID $parent_pid ($parent )." >> $output_dir/tmpfolder/process-checks.tmp
            fi
          else
            echo -e "\nUnexpected parent process for$child: PPID $ppid (could not map associated process name) instead of PPID $parent_pid ($parent )." >> $output_dir/tmpfolder/process-checks.tmp
          fi
        fi     
      done < $output_dir/tmpfolder/child-ppids.tmp
    fi
  done
  # verify processes are running in expected sessions:
  for process in " wininit.exe" " services.exe" " lsass.exe" " svchost.exe" " lsm.exe" " winlogon.exe"; do
    if [[ $process = " csrss.exe" ]] || [[ $process = " wininit.exe" ]] || [[ $process = " services.exe" ]] || [[ $process = " lsass.exe" ]] || [[ $process = " svchost.exe" ]]|| [[ $process = " lsm.exe" ]]; then session="0"; fi
    if [[ $process = " winlogon.exe" ]]; then session="1"; fi
    cat $output_dir/pslist/infected-pslist.txt | grep $process | tr -s ' ' | cut -d ' ' -f 7 > $output_dir/tmpfolder/process_sessions.tmp
    while read psession; do
      if [[ $psession != $session ]] ; then
        echo -e "\nProcess$process running in unexpected session ($psession instead of $session):" >> $output_dir/tmpfolder/process-checks.tmp
        sed -n '2p' $output_dir/pslist/infected-pslist.txt >> $output_dir/tmpfolder/process-checks.tmp
        sed -n '3p' $output_dir/pslist/infected-pslist.txt >> $output_dir/tmpfolder/process-checks.tmp
        cat $output_dir/pslist/infected-pslist.txt | grep $process >> $output_dir/tmpfolder/process-checks.tmp
      fi
    done < $output_dir/tmpfolder/process_sessions.tmp
  done

  # verify if any processes have suspicious l33t names:
  cat $output_dir/psscan/infected-psscan.txt | grep -E -i "snss|crss|cssrs|csrsss|lass|isass|lssass|lsasss|scvh|svch0st|svhos|svchst|lsn|g0n|l0g|nvcpl|rundii" > $output_dir/tmpfolder/suspicious_process.tmp
  if [[ -s $output_dir/tmpfolder/suspicious_process.tmp ]]; then
    echo -e "\nProcesses with suspicious names:" >> $output_dir/tmpfolder/process-checks.tmp
    sed -n '2p' $output_dir/psscan/infected-psscan.txt >> $output_dir/tmpfolder/process-checks.tmp
    sed -n '3p' $output_dir/psscan/infected-psscan.txt >> $output_dir/tmpfolder/process-checks.tmp
    cat $output_dir/tmpfolder/suspicious_process.tmp >> $output_dir/tmpfolder/process-checks.tmp
  fi

  # verify if any hacker tools were used in process list:
  cat $output_dir/psscan/infected-psscan.txt | grep -E -i $hacker_process_regex > $output_dir/tmpfolder/suspicious_tools.tmp
  if [[ -s $output_dir/tmpfolder/suspicious_tools.tmp ]]; then
    echo -e "\nSuspicious processes that may have been used for remote execution, lateral movement or privilege escalation:" >> $output_dir/tmpfolder/process-checks.tmp
    sed -n '2p' $output_dir/psscan/infected-psscan.txt >> $output_dir/tmpfolder/process-checks.tmp
    sed -n '3p' $output_dir/psscan/infected-psscan.txt >> $output_dir/tmpfolder/process-checks.tmp
    cat $output_dir/tmpfolder/suspicious_tools.tmp >> $output_dir/tmpfolder/process-checks.tmp
  fi

  # check process executable path:
  for process in "smss.exe" "crss.exe" "wininit.exe" "services.exe" "lsass.exe" "svchost.exe" "lsm.exe" "explorer.exe" "winlogon"; do
    if [[ $process == "smss.exe" ]]; then processpath="\systemroot\system32\smss.exe" ; fi
    if [[ $process == "crss.exe" ]]; then processpath="\windows\system32\csrss.exe" ; fi
    if [[ $process == "wininit.exe" ]]; then processpath="\windows\system32\wininit.exe" ; fi
    if [[ $process == "services.exe" ]]; then processpath="\windows\system32\services.exe" ; fi
    if [[ $process == "lsass.exe" ]]; then processpath="\windows\system32\lsass.exe" ; fi
    if [[ $process == "svchost.exe" ]]; then processpath="\windows\system32\svchost.exe" ; fi
    if [[ $process == "lsm.exe" ]]; then processpath="\windows\system32\lsm.exe" ; fi
    if [[ $process == "explorer.exe" ]]; then processpath="\windows\explorer.exe" ; fi
    if [[ $process == "winlogon.exe" ]]; then processpath="\windows\system32\winlogon.exe" ; fi
    cat $output_dir/dlllist/infected-dlllist.txt | grep -i -A 1 $process | grep "Command line" | grep -o '\\.*' | cut -d ' ' -f 1 | tr '[:upper:]' '[:lower:]' | sed 's,\\,\\\\,g' > $output_dir/tmpfolder/path_list.tmp
    if [[ -s $output_dir/tmpfolder/path_list.tmp ]]; then
      while read path; do
        if [[ "$path" != "$processpath" ]]; then
          echo -e "\nProcess $process is running from $path instead of $processpath" >> $output_dir/tmpfolder/process-checks.tmp
        fi
      done < $output_dir/tmpfolder/path_list.tmp
    fi
  done

  # detect process hollowing
  mkdir $output_dir/tmpfolder/hollowing
  vol.py --profile=$profile -f $infected_memory_image procdump -u -D $output_dir/tmpfolder/hollowing/ &> /dev/null
  cat $output_dir/psscan/infected-psscan.txt | tr -s ' ' | cut -d ' ' -f 2 | cut -d '.' -f 1 | sort | uniq > $output_dir/tmpfolder/process-names.tmp
  tail -n +4 $output_dir/tmpfolder/process-names.tmp > $output_dir/tmpfolder/procnames.tmp
  while read process ; do
    cat $output_dir/psscan/infected-psscan.txt | grep -i $process | tr -s ' ' | cut -d ' ' -f 3 > $output_dir/tmpfolder/$process-pids.tmp
    touch $output_dir/tmpfolder/$process-size.tmp
    while read pid ; do
      ls -l $output_dir/tmpfolder/hollowing/ | tr -s ' ' | cut -d ' ' -f5,9 | grep -i "executable.$pid.exe" | cut -d ' ' -f 1 >> $output_dir/tmpfolder/$process-size.tmp
    done < $output_dir/tmpfolder/$process-pids.tmp
    cat $output_dir/tmpfolder/$process-size.tmp | uniq > $output_dir/tmpfolder/$process-size-uniq.tmp
    lines=`wc -l < $output_dir/tmpfolder/$process-size-uniq.tmp`
    if [[ $lines != 1 ]] && [[ $lines != 0 ]]  ; then 
      echo -e "\nPossible process hollowing detected in $process (unusual size):" >> $output_dir/tmpfolder/process-checks.tmp
      echo -e "Process		PID	Size" >> $output_dir/tmpfolder/process-checks.tmp
      echo -e "-----------------------------------" >> $output_dir/tmpfolder/process-checks.tmp
      while read pid ; do
        echo -e "$process		$pid	`ls -l $output_dir/tmpfolder/hollowing/ | tr -s ' ' | cut -d ' ' -f5,9 | grep -i "executable.$pid.exe" | cut -d ' ' -f 1`" >> $output_dir/tmpfolder/process-checks.tmp
      done < $output_dir/tmpfolder/$process-pids.tmp   
    fi
  done < $output_dir/tmpfolder/procnames.tmp

  # processing ldrmodules output
  plugin="ldrmodules"
  # highlight new hidden DLLs
  cat $output_dir/$plugin/diff-$plugin.txt | grep "False" | grep -E -v -i "system32|explorer.exe|iexplore.exe" | sort | uniq > $output_dir/tmpfolder/$plugin.tmp
  if [[ -s $output_dir/tmpfolder/$plugin.tmp ]] ; then
    echo -e "\nSuspicious new $plugin entries:" >> $output_dir/tmpfolder/process-checks.tmp
    sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/tmpfolder/process-checks.tmp
    sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/tmpfolder/process-checks.tmp
    cat $output_dir/tmpfolder/$plugin.tmp >> $output_dir/tmpfolder/process-checks.tmp
  fi
  # find highly suspicious DLLs used for password stealing
  cat $output_dir/$plugin/diff-$plugin.txt | grep -E -i $hacker_dll_regex | sort | uniq >> $output_dir/tmpfolder/ldrmodule_hacker.tmp
  if [[ -s $output_dir/tmpfolder/ldrmodule_hacker.tmp ]] ; then
    echo -e "\nHighly suspicious DLLs:" >> $output_dir/tmpfolder/process-checks.tmp
    sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/tmpfolder/process-checks.tmp
    sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/tmpfolder/process-checks.tmp
    cat $output_dir/tmpfolder/ldrmodule_hacker.tmp >> $output_dir/tmpfolder/process-checks.tmp
  fi

  # processing dlllist output:
  plugin="dlllist"
  cat $output_dir/$plugin/diff-$plugin.txt | grep "Command line" | grep -E -v -i "system32|explorer.exe|iexplore.exe" | sed -e 's/Command line : //' | sort | uniq > $output_dir/tmpfolder/execs.tmp
  if [[ -s $output_dir/tmpfolder/execs.tmp ]] ; then
    echo -e "\nSuspicious new executables from dlllist" >> $output_dir/tmpfolder/process-checks.tmp
    cat $output_dir/tmpfolder/execs.tmp >> $output_dir/tmpfolder/process-checks.tmp
  fi

  cat $output_dir/$plugin/diff-$plugin.txt | grep -o -E "C:.*.dll" | grep -v -i "System32" | uniq | sort > $output_dir/tmpfolder/dlls.tmp
  if [[ -s $output_dir/tmpfolder/dlls.tmp ]] ; then
    echo -e "\nSuspicious new DLLs" >> $output_dir/tmpfolder/process-checks.tmp
    cat $output_dir/tmpfolder/dlls.tmp >> $output_dir/tmpfolder/process-checks.tmp
  fi

  # analysing import tables in new processes
  plugin=impscan
  tail -n +4 $output_dir/psscan/diff-psscan.txt | tr -s ' ' | cut -d " " -f 3 | sort | uniq > $output_dir/tmpfolder/pids.tmp
  while read pid; do
    vol.py --profile=$profile -f $infected_memory_image $plugin -p $pid &> $output_dir/tmpfolder/$pid-imports.tmp
    process=`tail -n +4 $output_dir/psscan/diff-psscan.txt | tr -s ' ' | cut -d ' ' -f 1-3 | grep -i " "$pid | cut -d ' ' -f 2 | sort | uniq`
    # search for password extraction import functions 
    cat $output_dir/tmpfolder/$pid-imports.tmp | grep -i -E "SamLookupDomainInSamServer|NlpGetPrimaryCredential|LsaEnumerateLogonSessions|SamOpenDomain|SamOpenUser|SamGetPrivateData|SamConnect|SamRidToSid|PowerCreateRequest|SeDebugPrivilege" > $output_dir/tmpfolder/$pid-imports-password.tmp
    if [[ -s $output_dir/tmpfolder/$pid-imports-password.tmp ]] ; then
      echo -e "\nSuspicious import in process $process (can be used for password extraction):" >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '2p' $output_dir/tmpfolder/tmpfolder/$pid-imports.tmp >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '3p' $output_dir/tmpfolder/$pid-imports.tmp >> $output_dir/tmpfolder/process-checks.tmp
      cat $output_dir/tmpfolder/$pid-imports-password.tmp >> $output_dir/tmpfolder/process-checks.tmp
    fi
    # search for process injection import functions
    cat $output_dir/tmpfolder/$pid-imports.tmp | grep -i -E "VirtualAllocEx|AllocateVirtualMemory|VirtualProtectEx|ProtectVirtualMemory|CreateProcess|LoadLibrary|LdrLoadDll|CreateToolhelp32Snapshot|QuerySystemInformation|EnumProcesses|WriteProcessMemory|WriteVirtualMemory|CreateRemoteThread|ResumeThread|SetThreadContext|SetContextThread|QueueUserAPC|QueueApcThread" > $output_dir/tmpfolder/$pid-imports-injection.tmp
    if [[ -s $output_dir/tmpfolder/$pid-imports-injection.tmp ]] ; then
      echo -e "\nSuspicious import in process $process (can be used for process injection):" >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '2p' $output_dir/tmpfolder/$pid-imports.tmp >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '3p' $output_dir/tmpfolder/$pid-imports.tmp >> $output_dir/tmpfolder/process-checks.tmp
      cat $output_dir/tmpfolder/$pid-imports-injection.tmp >> $output_dir/tmpfolder/process-checks.tmp
    fi
    #search for web request import functions
    cat $output_dir/tmpfolder/$pid-imports.tmp | grep -i -E "HttpSendRequestA|HttpSendRequestW|HttpSendRequestExA|HttpSendRequestExW" > $output_dir/tmpfolder/$pid-imports-web.tmp
    if [[ -s $output_dir/tmpfolder/$pid-imports-web.tmp ]] ; then
      echo -e "\nSuspicious import in process $process (can be used for web requests):" >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '2p' $output_dir/tmpfolder/$pid-imports.tmp >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '3p' $output_dir/tmpfolder/$pid-imports.tmp >> $output_dir/tmpfolder/process-checks.tmp
      cat $output_dir/tmpfolder/$pid-imports-web.tmp >> $output_dir/tmpfolder/process-checks.tmp
    fi
    #search for uac bypass import funtions
    cat $output_dir/tmpfolder/$pid-imports.tmp | grep -i -E "AllocateAndInitializeSid|EqualSid|RtlQueryElevationFlags|GetTokenInformation|GetSidSubAuthority|GetSidSubAuthorityCount" > $output_dir/tmpfolder/$pid-imports-uac.tmp
    if [[ -s $output_dir/tmpfolder/$pid-imports-uac.tmp ]] ; then
      echo -e "\nSuspicious import in process $process (can be used for uac bypass):" >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '2p' $output_dir/tmpfolder/$pid-imports.tmp >> $output_dir/tmpfolder/process-checks.tmp
      sed -n '3p' $output_dir/tmpfolder/$pid-imports.tmp >> $output_dir/tmpfolder/process-checks.tmp
      cat $output_dir/tmpfolder/$pid-imports-uac.tmp >> $output_dir/tmpfolder/process-checks.tmp
    fi
  done < $output_dir/tmpfolder/pids.tmp

fi

################################ REGISTRY CHECKS ################################
if [[ $@ =~ "--registry-checks" ]] ; then
  echo -e "Searching for changes in registry keys..."
  touch $output_dir/tmpfolder/registry_checks.tmp
  plugin="printkey"
  for key in "Microsoft\Windows\CurrentVersion\RunOnce" "Microsoft\Windows\CurrentVersion\Run" "Microsoft\Windows\CurrentVersion\RunServices" "Microsoft\Windows\CurrentVersion\RunServicesOnce" "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "Microsoft\Security Center\Svc" ; do
    vol.py --profile=$profile -f $baseline_memory_image $plugin -K $key &> $output_dir/tmpfolder/base.tmp &
    vol.py --profile=$profile -f $infected_memory_image $plugin -K $key &> $output_dir/tmpfolder/inf.tmp &
    wait
    tr < $output_dir/tmpfolder/base.tmp -d '\000' > $output_dir/tmpfolder/baseline.tmp
    tr < $output_dir/tmpfolder/inf.tmp -d '\000' > $output_dir/tmpfolder/infected.tmp
    diff $output_dir/tmpfolder/baseline.tmp $output_dir/tmpfolder/infected.tmp | grep -E "^>" | sed 's/^..//' &> $output_dir/tmpfolder/diff.tmp
    if [[ -s $output_dir/tmpfolder/diff.tmp ]] ; then
      echo -e "\nThe registry key $key has changed:\n" >> $output_dir/tmpfolder/registry_checks.tmp
      tail -n +2 $output_dir/tmpfolder/infected.tmp >> $output_dir/tmpfolder/registry_checks.tmp
    fi
  done
fi

################################ STRING CHECKS ################################
if [[ $@ =~ "--string-checks" ]] ; then
  echo -e "Hunting for badness in memory strings..."
  hacker_string_regex="'sysinternal|psexec|WCEServicePipe|mimikatz|credentials.txt|wce_krbtkts'"
  #running strings
  plugin="strings"
  mkdir $output_dir/$plugin
  strings -a -td $baseline_memory_image > $output_dir/$plugin/baseline-$plugin.txt
  strings -a -td $infected_memory_image > $output_dir/$plugin/infected-$plugin.txt
  diff $output_dir/$plugin/baseline-$plugin.txt $output_dir/$plugin/infected-$plugin.txt | grep -E "^>" | sed 's/^..//' &> $output_dir/$plugin/diff-$plugin.txt
  vol.py --profile=$profile -f $infected_memory_image $plugin --string-file=$output_dir/$plugin/diff-$plugin.txt &> $output_dir/$plugin/diff-$plugin-vol.txt
  #finding new emails, domains and IPs
  cat $output_dir/strings/diff-strings-vol.txt | perl -e 'while(<>){if(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/){print $_;}}' &>> $output_dir/strings/diff-ips-domains-vol.txt
  cat $output_dir/strings/diff-strings-vol.txt | perl -e 'while(<>){ if(/(http|https|ftp|mail)\:[\/\w.]+/){print $_;}}' &>> $output_dir/strings/diff-ips-domains-vol.txt
  cat $output_dir/strings/diff-strings-vol.txt | grep -E -o "\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b" &>> $output_dir/strings/diff-ips-domains-vol.txt
  #finding suspicious executable names in new strings
  touch $output_dir/tmpfolder/string_checks.tmp
  touch $output_dir/tmpfolder/susp_string.tmp
  cat $output_dir/strings/diff-strings-vol.txt | grep -i -E $hacker_string_regex > $output_dir/tmpfolder/susp_string.tmp
  if [[ -s $output_dir/tmpfolder/susp_string.tmp ]] ; then
    cat $output_dir/tmpfolder/susp_string.tmp >> $output_dir/tmpfolder/string_checks.tmp
  fi
  #finding ips/domainsemails in dumped malfind processes
  plugin="malfind"
  strings -a -td $output_dir/malfind/dump-dir-infected/* > $output_dir/tmpfolder/malfind-strings.tmp
  cat $output_dir/tmpfolder/malfind-strings.tmp | grep -o -E '\b(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]' | uniq >> $output_dir/tmpfolder/infected-ip-domains.tmp
  cat $output_dir/tmpfolder/malfind-strings.tmp | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | uniq >> $output_dir/tmpfolder/infected-ip-domains.tmp
  cat $output_dir/tmpfolder/malfind-strings.tmp | grep -E -o "\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b" | uniq >> $output_dir/tmpfolder/infected-ip-domains.tmp
  if [[ -s $output_dir/tmpfolder/infected-ip-domains.tmp ]] ; then
    cat $output_dir/tmpfolder/infected-ip-domains.tmp >> $output_dir/tmpfolder/string_checks.tmp
  fi
  rm $output_dir/strings/baseline-strings.txt $output_dir/strings/infected-strings.txt $output_dir/strings/diff-strings.txt &> /dev/null
fi

################################ REPORT CREATION ################################
if [[ $@ =~ "--no-report" ]] ; then
  endtime=$(date +%s)
  echo -e "\nAll done in $(($endtime - $starttime)) seconds."
  rm -r $output_dir/tmpfolder &> /dev/null
  exit
  notify-send "VolDiff execution completed."
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
touch $output_dir/tmpfolder/no_new_entries.tmp
for plugin in "${plugins_to_report[@]}"
do
  if [[ -s $output_dir/$plugin/diff-$plugin.txt ]] ; then
     # special processing for psxview:
    if [[ $plugin = "psxview" ]] ; then
      cat $output_dir/psxview/diff-psxview.txt | grep "[0-9] False" > $output_dir/tmpfolder/hidden.tmp
      if [[ -s $output_dir/tmpfolder/hidden.tmp ]] ; then
        echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
        echo -e "===========================================================================\n" >> $output_dir/$report
        sed -n '2p' $output_dir/psxview/infected-psxview.txt >> $output_dir/$report
        sed -n '3p' $output_dir/psxview/infected-psxview.txt >> $output_dir/$report
        cat $output_dir/tmpfolder/hidden.tmp >> $output_dir/$report
        if [[ $@ =~ "--add-hints" ]] ; then
          echo -e "\nHint: psxview enumerates processes in 7 different ways. The output above is filtered to only display processes that were hidden." >> $output_dir/$report
        fi
      else
        echo -e "$plugin" >> $output_dir/tmpfolder/no_new_entries.tmp 
      fi
    # processing pslist and psscan output:
    elif [[ $plugin = "pslist"  ]] || [[ $plugin = "psscan"  ]] ; then
     echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
     echo -e "===========================================================================\n" >> $output_dir/$report
     sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
     sed -n '3p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
     cat $output_dir/$plugin/baseline-$plugin.txt | tr -s ' ' | cut -d " " -f 3 > $output_dir/tmpfolder/baseline-pids.tmp
     cat $output_dir/$plugin/infected-$plugin.txt | tr -s ' ' | cut -d " " -f 3  > $output_dir/tmpfolder/infected-pids.tmp
     diff $output_dir/tmpfolder/baseline-pids.tmp $output_dir/tmpfolder/infected-pids.tmp | grep -E "^>" | sed 's/^..//' | uniq &>> $output_dir/tmpfolder/unique-new-pids.tmp
     while read pid; do
       cat $output_dir/$plugin/infected-$plugin.txt | grep $pid >> $output_dir/$report
     done < $output_dir/tmpfolder/unique-new-pids.tmp
    #processing netscan output
    elif [[ $plugin = "netscan"  ]] ; then
      echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
      echo -e "===========================================================================\n" >> $output_dir/$report
      sed -n '2p' $output_dir/$plugin/infected-$plugin.txt >> $output_dir/$report
      cat $output_dir/$plugin/diff-$plugin.txt >> $output_dir/$report
    # filtering deskscan output:
    elif [[ $plugin = "deskscan"  ]] ; then
      cat $output_dir/$plugin/diff-$plugin.txt | grep "Desktop:" >> $output_dir/tmpfolder/$plugin.tmp
      if [[ -s $output_dir/tmpfolder/$plugin.tmp ]] ; then
        echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
        echo -e "===========================================================================\n" >> $output_dir/$report
        cat $output_dir/tmpfolder/$plugin.tmp >> $output_dir/$report
        if [[ $@ =~ "--add-hints" ]] ; then
          echo -e "\nHint: Use wintree to view a tree of the windows in suspicious desktops." >> $output_dir/$report
        fi
      else
        echo -e "$plugin" >> $output_dir/tmpfolder/no_new_entries.tmp 
      fi
    # filtering timeliner results:
    elif [[ $plugin = "timeliner" ]] ; then
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PROCESS" >> $output_dir/tmpfolder/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "NETWORK CONNECT" >> $output_dir/tmpfolder/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PE HEADER (module)" >> $output_dir/tmpfolder/$plugin.tmp
     cat $output_dir/$plugin/diff-$plugin.txt | grep "PE HEADER (exe)" >> $output_dir/tmpfolder/$plugin.tmp
     echo -e "\n\nSuspicious new $plugin entries" >> $output_dir/$report
     echo -e "===========================================================================\n" >> $output_dir/$report
     cat $output_dir/tmpfolder/$plugin.tmp | sort >> $output_dir/$report
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
    # adding hints to help in further analysis:
    if [[ $@ =~ "--add-hints" ]] ; then
      if [[ $plugin = "malfind" ]] ; then
        echo -e "\nHint: Suspicious malfind processes were dumped to disk, and can be reversed as normal or uploaded to VirusTotal." >> $output_dir/$report
      fi
      if [[ $plugin = "drivermodule" ]] ; then
        echo -e "\nHint: Drivers without a module (UNKNOWN) should be considered as suspicious. Use moddump -b to dump suspicious drivers from memory to disk." >> $output_dir/$report
      fi
      if [[ $plugin = "driverscan" ]] ; then
        echo -e "\nHint: Drivers that have no associated service should be considered as suspicious. Use moddump -b to dump suspicious drivers from memory to disk." >> $output_dir/$report
      fi
      if [[ $plugin = "psscan" ]] ; then
        echo -e "\nHint: Use procexedump to dump suspcious processes from memory to disk." >> $output_dir/$report
      fi
      if [[ $plugin = "netscan" ]] ; then
        echo -e "\nHint: Translate suspicious IPs to domains using Google/VirusTotal, and search for the associated domains in memory strings." >> $output_dir/$report
      fi
      if [[ $plugin = "privs" ]] ; then
        echo -e "\nHint: privs was run with the -s switch. It will only show the privileges that were not enabled by default." >> $output_dir/$report
      fi
      if [[ $plugin = "idt" ]] ; then
        echo -e "\nHint: Look for hooks that point inside anomalous modules. Some interrupts can point inside rootkit code." >> $output_dir/$report
      fi
      if [[ $plugin = "getsids" ]] ; then
        echo -e "\nHint: Check the output of handles for suspicious processes, and grep for mutants, then Google those. Also grep the output of ldrmodules for any hidden dlls associated with suspicious processes. Use dlldump to dump suspicious DLLs from memory to disk." >> $output_dir/$report
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
    echo -e "$plugin" >> $output_dir/tmpfolder/no_new_entries.tmp 
  fi
done

# display list of plugins with no notable changes:
if [[ -s $output_dir/tmpfolder/no_new_entries.tmp ]]; then
  echo -e "\n\nNo notable changes to highlight from the following plugins" >> $output_dir/$report
  echo -e "===========================================================================\n" >> $output_dir/$report
  cat $output_dir/tmpfolder/no_new_entries.tmp >> $output_dir/$report
fi

# add identified process anamalies to the report:
if [[ $@ =~ "--process-checks" ]] ; then
  if [[ -s $output_dir/tmpfolder/process-checks.tmp ]]; then
    echo -e "\n\nProcess anomalies" >> $output_dir/$report
    echo -e "===========================================================================" >> $output_dir/$report
    cat $output_dir/tmpfolder/process-checks.tmp >> $output_dir/$report
  fi
fi
# add identified registry anamalies to the report:
if [[ $@ =~ "--registry-checks" ]] ; then
  if [[ -s $output_dir/tmpfolder/registry_checks.tmp ]]; then
    echo -e "\n\nChanges in registry keys commonly used for persistence" >> $output_dir/$report
    echo -e "===========================================================================" >> $output_dir/$report
    cat $output_dir/tmpfolder/registry_checks.tmp >> $output_dir/$report
  fi
fi

# add identified suspicious strings to the report:
if [[ $@ =~ "--string-checks" ]] ; then
  if [[ -s $output_dir/tmpfolder/string_checks.tmp ]]; then
    echo -e "\n\nSuspicious new strings found in memory" >> $output_dir/$report
    echo -e "===========================================================================\n" >> $output_dir/$report
    cat $output_dir/tmpfolder/string_checks.tmp >> $output_dir/$report
  fi
fi

echo -e "\n\nEnd of report." >> $output_dir/$report
rm -r $output_dir/tmpfolder &> /dev/null

endtime=$(date +%s)
echo -e "\nAll done in $(($endtime - $starttime)) seconds, report saved to $output_dir/$report."
notify-send "VolDiff execution completed."
