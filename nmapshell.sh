#!/bin/bash

target=""
targets=""
speed=3
udp_scan="false"
full_scan="false"
tcp_scan="false"
vuln="false"
scan_count=0
outdir="./nmap_results"



RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'

BOLD='\033[1m'

RESET='\033[0m'


info()        { echo -e "${CYAN}[*]${RESET} $1"; }
success()     { echo -e "${GREEN}[+]${RESET} $1"; }
warn()        { echo -e "${YELLOW}[~]${RESET} $1"; }
error()       { echo -e "${RED}[!]${RESET} $1"; }
section()     { echo -e "\n${BOLD}${BLUE}══════════════ $1 ══════════════${RESET}"; }
count_lines() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

usage(){
    #how to use the script
    echo -e "${BOLD}Usage:${RESET} $0 -t <target> | -T <targets_file> [-s <speed>] [-u] [-f] [-S] [-v] [-o] [-h]"
    echo -e "\n${BOLD}Options:${RESET}"
    echo -e "  ${BOLD}-t${RESET} <target>        Specify a single target IP or hostname"
    echo -e "  ${BOLD}-T${RESET} <targets_file>  Specify a file containing a list of targets (one per line)"
    echo -e "  ${BOLD}-s${RESET} <speed>         Specify the scan speed (1-5, default: 3)"
    echo -e "  ${BOLD}-u${RESET}                  Perform a UDP scan"
    echo -e "  ${BOLD}-f${RESET}                  Perform a full scan (TCP and UDP)"
    echo -e "  ${BOLD}-S${RESET}                  Perform a TCP scan"
    echo -e "  ${BOLD}-v${RESET}                  Perform a vulnerability scan using Nmap NSE scripts"
    echo -e "  ${BOLD}-o${RESET} <output_dir>     Specify the output directory for scan results (default: current directory)"
    echo -e "  ${BOLD}-h${RESET}                  Display this help message"
    exit 1 
}


while getopts "t:T:s:o:ufShv" opt; do
    case "$opt" in
    t) target="$OPTARG" ;;
    T) targets="$OPTARG" ;;
    s) speed="$OPTARG" ;;
    u) udp_scan="true"; ((scan_count++)) ;;
    f) full_scan="true"; ((scan_count++)) ;;
    S) tcp_scan="true"; ((scan_count++)) ;;
    v) vuln="true" ;;
    o) outdir="$OPTARG" ;;
    h) usage ;;
    *) usage ;;  
    esac
done


#nmap installation check
verify_nmap_installed(){
     if ! command -v nmap &>/dev/null;then
        error "nmap is not installed, please install nmap and try again."
        exit 1
    fi
}

# field validation checks
field_validationChecks(){
#  check for required fields
    if [[ -z "$target"  &&  -z "$targets" ]]; then
        warn "Please specify a target (-t) or a targets file (-T) that exists."
        usage
    elif [[ -n "$targets" && ! -f "$targets" ]]; then
       warn "The specified targets file does not exist: $targets"
        usage

    fi

#  check for required scan type
    if [[ "$udp_scan" == "false" && "$tcp_scan" == "false" && "$full_scan" == "false" ]]; then
        warn "Please specify a scan type: -u for UDP, -S for TCP, or -f for full scan."
        usage

    fi
#  validate scan counts
    if [ "$scan_count" -gt 1 ]; then
        warn "please choose only one scan type"
        usage
    elif [ "$scan_count" -eq 0 ]; then
        warn "Please specify a scan type: -u for UDP, -S for TCP, or -f for full scan."
        usage
    fi
#  validate scan speed 
    if [[ "$speed" -gt 5  || "$speed" -eq 0 || "$speed" -lt 0 ]]; then
        warn "Specify the scan speed (1-5, default: 3)"
        usage
    fi
}

mkdir -p "$outdir"

get_args(){  
    if [ -n "$target" ]; then
        echo "$target"
    else 
        echo "-iL $targets"
    fi
}

# tcp port check
run_OpenPortCheck(){
    section "Scanning For Open Ports"
    tcp_portscan=$(nmap -Pn -T"$speed" -sS $target_args -p- | awk -F'/' '/^[0-9]+\/(tcp|udp)[[:space:]]+open/ {print $1}' | paste -sd, -)
    
    if [ -z "$tcp_portscan" ]; then
    	 info "No open ports found"       
    else  
        count=$(echo "$tcp_portscan" | tr ',' '\n' | wc -l)
        info "Open tcp ports found $count"
    fi
}

#Tcp service enumeratioin and default script
run_serviceFingerprint(){
    section "Running service version and default scripts"
    
    if [ -n "$count" ]; then
        nmap -Pn -T"$speed" -sV -sC -p"$tcp_portscan" $target_args | tee "$outdir/tcp_scan.txt"
    else
        info "No open ports found"
    fi

}

# udp port check
run_OpenPortCheck_udp(){
    section "Scanning For Open udp Ports"
    udp_portscan=$(nmap -Pn -T"$speed" -p- -sU $target_args | awk -F'/' '/^[0-9]+\/(tcp|udp)[[:space:]]+open/ {print $1}'| paste -sd, -)
    
    if [ -z "$udp_portscan" ]; then
        info "No udp port found"
    else 
    	udp_count=$(echo "$udp_portscan" | tr ',' '\n' | wc -l)
        info "udp ports found: $udp_count"
    fi

}

# udp service enumeration and default script check
run_serviceFingerprint_udp(){
    section "Running service version and default scripts"

    if [ -n "$udp_count" ]; then
        nmap -Pn -T"$speed" -sU -sV -sC -p"$udp_portscan" $target_args | tee "$outdir/udp_scan.txt"
    else 
        info "No open port found"
    fi
} 

run_tcp_vulnerabilityScan(){
    section "Running Nmap NSE Vulnerability Scanner on $target..."
    nmap -sV --script vulners $target_args -p"$tcp_portscan" | tee "$outdir/tcp_vuln_scan.txt"
}

run_udp_vulnerabilityScan(){
    section "Running Nmap NSE Vulnerability Scanner on $target..."
    nmap -sU -sV --script vulners $target_args -p"$udp_portscan" | tee "$outdir/udp_vuln_scan.txt"
}

run_tcpscan(){
    run_OpenPortCheck
    run_serviceFingerprint
}

run_udpscan(){
    run_OpenPortCheck_udp
    run_serviceFingerprint_udp
}

run_full_scan(){
    run_tcpscan
    run_udpscan
}


run_nmap(){
    if [[ "$tcp_scan" == "true" ]]; then
        run_tcpscan
    elif [[ "$udp_scan" == "true" ]]; then
        run_udpscan
    elif [[ "$full_scan" == "true" ]]; then
        run_full_scan
    else 
        warn "something went wrong"
        exit 1
    fi

    if [[ "$vuln" == "true" && "$tcp_scan" == "true" ]]; then
        run_tcp_vulnerabilityScan
    fi
    if [[ "$vuln" == "true" && "$full_scan" == "true" ]]; then
        run_tcp_vulnerabilityScan
         run_udp_vulnerabilityScan
    fi
    if [[ "$vuln" == "true" && "$udp_scan" == "true" ]]; then
        run_udp_vulnerabilityScan
    fi

}



report(){
    section "Generating Report"
    report(){
    section "Generating Report"

    # display scan type
    if [[ "$full_scan" == "true" ]]; then
        info "Scan type: Full (TCP + UDP)" 
    elif [[ "$tcp_scan" == "true" ]]; then
        info "Scan type: TCP"
    elif [[ "$udp_scan" == "true" ]]; then
        info "Scan type: UDP"
    fi

    # display host information
    if [ -n "$target" ]; then
        info "Target host: $target"
    else
        info "Target list: $targets"
    fi

    # display os information
    section "Host & OS Information"
    os_info=$(nmap -Pn -O $target_args 2>/dev/null)
    host_line=$(echo "$os_info" | grep -E "Nmap scan report for")
    os_line=$(echo "$os_info" | grep -E "^OS details:|^Aggressive OS guesses:|^Running:")

    if [ -n "$host_line" ]; then
        info "$host_line"
    fi
    if [ -n "$os_line" ]; then
        info "$os_line"
    else
        warn "OS detection inconclusive or requires root privileges"
    fi

    # display target information
    section "Target Information"
    info "Scan speed (T): $speed"
    info "Output directory: $outdir"

    # display device information
    device_line=$(echo "$os_info" | grep -E "^Device type:")
    if [ -n "$device_line" ]; then
        info "$device_line"
    else
        warn "Device type not determined"
    fi

    # display number of open ports
    section "Open Ports Summary"
    if [ -n "$tcp_portscan" ]; then
        tcp_open_count=$(echo "$tcp_portscan" | tr ',' '\n' | grep -c .)
        success "TCP open ports: $tcp_open_count ($tcp_portscan)"
    fi
    if [ -n "$udp_portscan" ]; then
        udp_open_count=$(echo "$udp_portscan" | tr ',' '\n' | grep -c .)
        success "UDP open ports: $udp_open_count ($udp_portscan)"
    fi
    if [ -z "$tcp_portscan" ] && [ -z "$udp_portscan" ]; then
        info "No open ports were found"
    fi

    # display port services version vulnerabilities/cve from nmap vulners script
    if [ -f "$outdir/tcp_vuln_scan.txt" ]; then
        section "TCP Vulnerability Findings (vulners)"
        grep -A1 "VULNERABLE\|CVE-" "$outdir/tcp_vuln_scan.txt" | grep -v "^--$" 
        if ! grep -q "CVE-" "$outdir/tcp_vuln_scan.txt" 2>/dev/null; then
            info "No CVEs reported by vulners for TCP services"
        fi
    fi
    if [ -f "$outdir/udp_vuln_scan.txt" ]; then
        section "UDP Vulnerability Findings (vulners)"
        grep -A1 "VULNERABLE\|CVE-" "$outdir/udp_vuln_scan.txt" | grep -v "^--$"
        if ! grep -q "CVE-" "$outdir/udp_vuln_scan.txt" 2>/dev/null; then
            info "No CVEs reported by vulners for UDP services"
        fi
    fi

    # display nmap -sC result for each open port where it found some information
    if [ -f "$outdir/tcp_scan.txt" ]; then
        section "TCP Script Scan (-sC) Findings"
        awk '/^[0-9]+\/tcp/{port=$0; print_block=1; next} /^[0-9]+\/udp/{print_block=0} /^\| / && print_block{print port; print; port=""}' "$outdir/tcp_scan.txt" | uniq
    fi
    if [ -f "$outdir/udp_scan.txt" ]; then
        section "UDP Script Scan (-sC) Findings"
        awk '/^[0-9]+\/udp/{port=$0; print_block=1; next} /^[0-9]+\/tcp/{print_block=0} /^\| / && print_block{print port; print; port=""}' "$outdir/udp_scan.txt" | uniq
    fi
}   
}

field_validationChecks
verify_nmap_installed
target_args=$(get_args)
run_nmap
report
