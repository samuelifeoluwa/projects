#!/usr/bin/env bash

# ─── Variables ───────────────────────────────────────────────────────────────
filename=""
output_dir="./wesploit_results"
block=""
wes_output=""
temp_file=""

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Logging ─────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[~]${RESET} $1"; }
error()   { echo -e "${RED}[!]${RESET} $1"; }
section() { echo -e "\n${BOLD}${BLUE}══════════════ $1 ══════════════${RESET}"; }

# ─── Usage ───────────────────────────────────────────────────────────────────
usage(){
    echo -e "${BOLD}Usage:${RESET} $0 -f <systeminfo.txt> [-o <output_dir>] [-h]"
    echo -e "\n${BOLD}Options:${RESET}"
    echo -e "  ${BOLD}-f${RESET} <systeminfo.txt>  Path to systeminfo output file (required)"
    echo -e "  ${BOLD}-o${RESET} <output_dir>       Output directory (default: ./wesploit_results)"
    echo -e "  ${BOLD}-h${RESET}                    Show this help message"
    exit 1
}

# ─── Parse Arguments ─────────────────────────────────────────────────────────
while getopts "f:o:h" opt; do
    case "$opt" in
        f) filename="$OPTARG" ;;
        o) output_dir="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ─── Find wes.py ─────────────────────────────────────────────────────────────
wes_path=$(command -v wes.py 2>/dev/null)
if [[ -z "$wes_path" ]]; then
    wes_path=$(find ~/ /opt /tools -name "wes.py" 2>/dev/null | head -1)
fi
wes_dir=$(dirname "$wes_path")

# ─── Verify Tools ────────────────────────────────────────────────────────────
verify_tool(){
    section "Checking Dependencies"

    if [[ -z "$wes_path" ]]; then
        error "wes.py not found. Install WES-NG: https://github.com/bitsadmin/wesng"
        exit 1
    else
        success "wes.py found at: $wes_path"
    fi

    if ! command -v python3 &>/dev/null; then
        error "python3 is not installed. Please install python3."
        exit 1
    else
        success "python3 found"
    fi

    if ! command -v searchsploit &>/dev/null; then
        error "searchsploit is not installed. Please install exploitdb."
        exit 1
    else
        success "searchsploit found"
    fi
}

# ─── Validate Input File ─────────────────────────────────────────────────────
required_field(){
    if [[ -z "$filename" || ! -f "$filename" ]]; then
        error "Please provide a valid systeminfo file with -f"
        usage
    fi
}

# ─── Run WES-NG ──────────────────────────────────────────────────────────────
run_wes(){
    section "Running WES-NG"
    filename=$(realpath "$filename")
    temp_file=$(mktemp)
    trap 'rm -f "$temp_file"' EXIT
    info "Running wes.py against $filename..."
    (cd "$wes_dir" && python3 wes.py "$filename") > "$temp_file"
    wes_output="$temp_file"
    success "WES-NG scan complete"
}

# ─── Process Each CVE Block ──────────────────────────────────────────────────
process_block(){
    [[ -z "$block" ]] && return

    cve=$(echo "$block"      | grep "^CVE:"      | awk -F': ' '{print $2}')
    severity=$(echo "$block" | grep "^Severity:" | awk -F': ' '{print $2}')
    impact=$(echo "$block"   | grep "^Impact:"   | awk -F': ' '{print $2}')
    exploit=$(echo "$block"  | grep "^Exploit:"  | awk -F': ' '{print $2}')
    title=$(echo "$block"    | grep "^Title:"    | awk -F': ' '{print $2}')
    kb=$(echo "$block"       | grep "^KB:"       | awk -F': ' '{print $2}')

    # skip empty CVE entries
    [[ -z "$cve" ]] && block="" && return

    # always add to cve_list for searchsploit
    echo "$cve" >> "$output_dir/cve_list.txt"

    if [[ "$exploit" != "n/a" && -n "$exploit" ]]; then
        echo "$severity|$cve|$impact|$exploit|$title|$kb" >> "$output_dir/has_exploit.txt"
    else
        echo "$severity|$cve|$impact|$exploit|$title|$kb" >> "$output_dir/no_exploit.txt"
    fi

    block=""
}

# ─── Parse WES-NG Output ─────────────────────────────────────────────────────
parse_wes(){
    section "Parsing WES-NG Output"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" ]]; then
            process_block
        else
            block+="$line"$'\n'
        fi
    done < "$wes_output"
    process_block  # catch last block if no trailing newline

    total=$(wc -l < "$output_dir/cve_list.txt" 2>/dev/null || echo 0)
    has=$(wc -l < "$output_dir/has_exploit.txt" 2>/dev/null || echo 0)
    success "Parsed $total CVEs — $has have a non-n/a exploit field in WES-NG"
}

# ─── Sort By Severity ────────────────────────────────────────────────────────
sort_by_severity(){
    [[ ! -f "$1" ]] && return
    while IFS='|' read -r severity cve impact exploit title kb; do
        case "$severity" in
            Critical)  echo "1|$severity|$cve|$impact|$exploit|$title|$kb" ;;
            Important) echo "2|$severity|$cve|$impact|$exploit|$title|$kb" ;;
            Moderate)  echo "3|$severity|$cve|$impact|$exploit|$title|$kb" ;;
            Low)       echo "4|$severity|$cve|$impact|$exploit|$title|$kb" ;;
            *)         echo "5|$severity|$cve|$impact|$exploit|$title|$kb" ;;
        esac
    done < "$1" | sort -t'|' -k1,1n | cut -d'|' -f2-
}

# ─── Run Searchsploit ────────────────────────────────────────────────────────
run_searchsploit(){
    section "Running Searchsploit Against CVE List"
    [[ ! -f "$output_dir/cve_list.txt" ]] && warn "No CVEs to check" && return

    > "$output_dir/searchsploit_results.txt"  # clear/create file

    while read -r cve_num; do
        [[ -z "$cve_num" ]] && continue
        result=$(searchsploit "$cve_num" --disable-colour 2>/dev/null)
        # only save if searchsploit found something (not just the empty table)
        if echo "$result" | grep -qv "No Results"; then
            echo "── $cve_num ──" >> "$output_dir/searchsploit_results.txt"
            echo "$result" >> "$output_dir/searchsploit_results.txt"
            echo "" >> "$output_dir/searchsploit_results.txt"
        fi
    done < "$output_dir/cve_list.txt"

    found=$(grep -c "^──" "$output_dir/searchsploit_results.txt" 2>/dev/null || echo 0)
    success "Searchsploit found results for $found CVEs"
}

# ─── Report ──────────────────────────────────────────────────────────────────
report(){
    section "Final Report"
    info "Input file:       $filename"
    info "Output directory: $output_dir"

    section "CVEs With Non-n/a Exploit Field (sorted by severity)"
    if [[ -f "$output_dir/has_exploit.txt" ]]; then
        sort_by_severity "$output_dir/has_exploit.txt" | while IFS='|' read -r severity cve impact exploit title kb; do
            echo -e "${RED}[$severity]${RESET} $cve | $impact"
            echo -e "    Title:   $title"
            echo -e "    KB:      $kb"
            echo -e "    Exploit: $exploit"
            echo ""
        done
    else
        info "None found"
    fi

    section "Searchsploit Matches"
    if [[ -s "$output_dir/searchsploit_results.txt" ]]; then
        cat "$output_dir/searchsploit_results.txt"
    else
        info "No searchsploit matches found"
    fi

    section "Output Files"
    success "has_exploit.txt         → CVEs with exploit reference in WES-NG"
    success "no_exploit.txt          → CVEs with n/a exploit field"
    success "cve_list.txt            → Full CVE list"
    success "searchsploit_results.txt → Searchsploit matches"
}

# ─── Main ────────────────────────────────────────────────────────────────────
verify_tool
required_field
mkdir -p "$output_dir"
run_wes
parse_wes
run_searchsploit
report
