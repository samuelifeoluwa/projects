
#!/bin/bash
target=""
ghp_token=""
rl=10
rlm=60
Header=""
threads=40
repo_url=""

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Output helpers ────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*"; }
section() { echo -e "\n${BOLD}${BLUE}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

count_lines() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  cat << 'EOF'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
        Automated Subdomain Recon Tool
EOF
  echo -e "${RESET}"
}

usage() {
    echo -e "${BOLD}Usage:${RESET} $0 -d <domain> [options]"
    echo ""
    echo -e "  ${CYAN}-d${RESET}  Target domain         (required)"
    echo -e "  ${CYAN}-t${RESET}  GitHub token"
    echo -e "  ${CYAN}-r${RESET}  Rate limit            (default: 10)"
    echo -e "  ${CYAN}-m${RESET}  Rate limit per minute (default: 60)"
    echo -e "  ${CYAN}-H${RESET}  HTTP header"
    echo -e "  ${CYAN}-c${RESET}  Threads               (default: 40)"
    echo -e "  ${CYAN}-R${RESET}  Repo URL for trufflehog/betterleaks"
    echo -e "  ${CYAN}-h${RESET}  Show this help"
    echo ""
    exit 0
}

while getopts "d:t:r:m:H:c:R:h" opt; do
    case "$opt" in
        d) target="$OPTARG" ;;
        t) ghp_token="$OPTARG" ;;
        r) rl="$OPTARG" ;;
        m) rlm="$OPTARG" ;;
        H) Header="$OPTARG" ;;
        c) threads="$OPTARG" ;;
        R) repo_url="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$target" ]; then
    error "-d <domain> is required"
    usage
fi

timestamp=$(date +%F_%H-%M)
outdir="recon_output/${target}/output"
mkdir -p "$outdir"

tools=(
    subfinder
    assetfinder
    amass
    github-subdomains
    httpx
    katana
    trufflehog
    betterleaks
    subzy
    dns-reaper
)

AVAILABLE=()

is_available() {
    local tool="$1"
    [[ " ${AVAILABLE[*]} " =~ " ${tool} " ]]
}

checktools() {
    section "Dependency Check"
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            AVAILABLE+=("$tool")
            success "$tool found → $(command -v "$tool")"
        else
            warn "$tool — not found, will be skipped"
        fi
    done
    echo ""
}

run_tools() {
    section "Subdomain Enumeration"
    for tool in "${AVAILABLE[@]}"; do
        case "$tool" in
            subfinder)
                info "Running subfinder on ${MAGENTA}$target${RESET}..."
                subfinder -d "$target" --silent 2>/dev/null > "${outdir}/subfinder.txt" || true
                local _sf_count
                _sf_count=$(count_lines "${outdir}/subfinder.txt")
                if [[ "$_sf_count" -eq 0 ]]; then
                    rm -f "${outdir}/subfinder.txt"
                    warn "subfinder — 0 results, file not saved"
                else
                    success "subfinder done → ${_sf_count} subdomains"
                fi
                ;;

            amass)
                info "Running amass on ${MAGENTA}$target${RESET}..."
                amass enum -d "$target" 2>/dev/null | tee "${outdir}/amass.txt"
                success "amass done → $(count_lines "${outdir}/amass.txt") subdomains"
                ;;

            assetfinder)
                info "Running assetfinder on ${MAGENTA}$target${RESET}..."
                assetfinder --subs-only "$target" 2>/dev/null > "${outdir}/assetfinder.txt" || true
                local _asf_count
                _asf_count=$(count_lines "${outdir}/assetfinder.txt")
                if [[ "$_asf_count" -eq 0 ]]; then
                    rm -f "${outdir}/assetfinder.txt"
                    warn "assetfinder — 0 results, file not saved"
                else
                    success "assetfinder done → ${_asf_count} subdomains"
                fi
                ;;

            github-subdomains)
                if [ -z "$ghp_token" ]; then
                    warn "No GitHub token provided — skipping github-subdomains"
                else
                    info "Running github-subdomains on ${MAGENTA}$target${RESET}..."
                    # github-subdomains prints its banner and error messages to stdout,
                    # so we filter: keep only lines that look like subdomains of the target.
                    local _gh_tmp="${outdir}/.gh_raw.txt"
                    github-subdomains -d "$target" -t "$ghp_token" 2>/dev/null > "$_gh_tmp" || true
                    grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" "$_gh_tmp" \
                        | grep -iE "(^|\.)${target//./\\.}$" \
                        > "${outdir}/github-subdomains.txt" || true
                    rm -f "$_gh_tmp"
                    local _gh_count
                    _gh_count=$(count_lines "${outdir}/github-subdomains.txt")
                    if [[ "$_gh_count" -eq 0 ]]; then
                        rm -f "${outdir}/github-subdomains.txt"
                        warn "github-subdomains — 0 results, file not saved"
                    else
                        success "github-subdomains done → ${_gh_count} subdomains"
                    fi
                fi
                ;;
        esac
    done
}

merge_output() {
    section "Merging Results"

    local merged="${outdir}/all_subdomains.txt"
    local tmp="${outdir}/.tmp_merge"

    local sub_tools=(subfinder assetfinder amass github-subdomains)

    for tool in "${sub_tools[@]}"; do
        local file="${outdir}/${tool}.txt"
        if [ -f "$file" ] && [ -s "$file" ]; then
            cat "$file" >> "$tmp"
            info "Merged: ${tool}.txt ($(count_lines "$file") lines)"
        else
            warn "${tool}.txt — empty or not found, skipping"
        fi
    done

    if [ -f "$tmp" ] && [ -s "$tmp" ]; then
        sort -u "$tmp" > "$merged"
        rm -f "$tmp"
        local count
        count=$(count_lines "$merged")
        echo ""
        success "${BOLD}${count} unique subdomains${RESET} → ${merged}"
    else
        rm -f "$tmp"
        error "No output was generated by any tool."
    fi
}

run_httpx() {
    if is_available "httpx"; then
        section "Live Host Probe (httpx)"
        local total
        total=$(count_lines "${outdir}/all_subdomains.txt")
        info "Probing ${BOLD}${total}${RESET} subdomains..."
        info "Rate limit: ${BOLD}${rl} rps / ${rlm} rpm${RESET} — threads: ${BOLD}${threads}${RESET}"
        echo ""

        httpx -l "${outdir}/all_subdomains.txt" \
              -sc -title -td -wp \
              -mc 200,201,301,302,303,304,401,403,404 \
              -t "$threads" -rl "$rl" -rlm "$rlm" \
              -H "$Header" \
              2>/dev/null > "${outdir}/live_hosts.txt"

        local count
        count=$(count_lines "${outdir}/live_hosts.txt")
        success "${BOLD}${count} live hosts${RESET} found → ${outdir}/live_hosts.txt"
        echo ""
        info "Status code breakdown:"
        echo ""

        # Status breakdown with colours
        local codes=(200 201 301 302 303 304 401 403 404)
        local labels=(
            "OK"
            "Created"
            "Moved Permanently"
            "Found"
            "See Other"
            "Not Modified"
            "Unauthorized"
            "Forbidden"
            "Not Found"
        )
        local colors=(
            "$GREEN"
            "$GREEN"
            "$CYAN"
            "$CYAN"
            "$CYAN"
            "$CYAN"
            "$YELLOW"
            "$YELLOW"
            "$RED"
        )

        for i in "${!codes[@]}"; do
            local code="${codes[$i]}"
            local label="${labels[$i]}"
            local color="${colors[$i]}"
            local n
            n=$(grep -c "\[${code}\]" "${outdir}/live_hosts.txt" 2>/dev/null || true)
            if [[ "$n" -gt 0 ]]; then
                printf "  ${color}[%-3s]${RESET}  ${BOLD}%-22s${RESET}  %s hosts\n" "$code" "$label" "$n"
            else
                printf "  ${DIM}[%-3s]  %-22s  0 hosts${RESET}\n" "$code" "$label"
            fi
        done
    else
        warn "httpx not found. Skipping"
    fi
}

run_katana() {
    if is_available "katana"; then
        section "Crawling (katana)"
        info "Extracting live URLs and crawling..."

        cut -d' ' -f1 "${outdir}/live_hosts.txt" > "${outdir}/live_urls.txt"

        katana -list "${outdir}/live_urls.txt" \
               -jc -d 2 \
               -H "$Header" \
               -rl "$rl" \
               -rlm "$rlm" \
               2>/dev/null > "${outdir}/katana.txt" || true

        local count
        count=$(count_lines "${outdir}/katana.txt")
        if [[ "$count" -eq 0 ]]; then
            rm -f "${outdir}/katana.txt"
            warn "katana — 0 URLs crawled, file not saved"
        else
            success "${BOLD}${count} URLs${RESET} crawled → ${outdir}/katana.txt"
        fi
    else
        warn "katana not found, skipping"
    fi
}

run_trufflehog() {
    section "Secret Scanning (trufflehog)"
    if is_available "trufflehog"; then
        if [ -z "$repo_url" ]; then
            warn "trufflehog skipped — no repo URL provided (-R flag)"
            return 0
        fi
        info "Running trufflehog on ${MAGENTA}${repo_url}${RESET}..."
        trufflehog github \
            --no-update \
            --token="${ghp_token}" \
            --repo="${repo_url}" \
            --results=verified \
            2>/dev/null > "${outdir}/trufflehog.txt" || true

        local count
        count=$(count_lines "${outdir}/trufflehog.txt")
        if [[ "$count" -eq 0 ]]; then
            rm -f "${outdir}/trufflehog.txt"
            warn "trufflehog — 0 findings, file not saved"
        else
            success "trufflehog done — ${BOLD}${count} findings${RESET} → ${outdir}/trufflehog.txt"
        fi
    else
        warn "trufflehog not found, skipping"
    fi
}

run_betterleaks() {
    section "Leak Scanning (betterleaks)"
    if is_available "betterleaks"; then
        if [ -z "$repo_url" ]; then
            warn "betterleaks skipped — no repo URL provided (-R flag)"
            return 0
        fi
        info "Running betterleaks on ${MAGENTA}${repo_url}${RESET}..."
        betterleaks github "${repo_url}" \
            --include issues,prs,actions,releases,gists \
            --token "${ghp_token}" \
            2>/dev/null > "${outdir}/betterleaks.txt" || true

        local count
        count=$(count_lines "${outdir}/betterleaks.txt")
        if [[ "$count" -eq 0 ]]; then
            rm -f "${outdir}/betterleaks.txt"
            warn "betterleaks — 0 findings, file not saved"
        else
            success "betterleaks done — ${BOLD}${count} findings${RESET} → ${outdir}/betterleaks.txt"
        fi
    else
        warn "betterleaks not found, skipping"
    fi
}

run_subzy() {
    section "Subdomain Takeover Check (subzy)"
    if is_available "subzy"; then
        info "Running subzy against live hosts..."
        # subzy always prints config/header lines; we only want VULN hits.
        # Capture full output for display, save only if actual findings exist.
        local _subzy_raw="${outdir}/.subzy_raw.txt"
        subzy run \
            --hide_fails \
            --concurrency "$threads" \
            --targets "${outdir}/live_hosts.txt" \
            --vuln 2>/dev/null > "$_subzy_raw" || true

        # Real finding lines contain a domain/URL — config/header lines don't.
        # Filter: keep only lines that have a dot followed by at least 2 alpha chars
        # (i.e. look like a hostname or URL). This drops all [ Yes/No/N ] config lines.
        grep -E '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' "$_subzy_raw" > "${outdir}/subzy.txt" 2>/dev/null || true
        rm -f "$_subzy_raw"

        local count
        count=$(count_lines "${outdir}/subzy.txt")
        if [[ "$count" -eq 0 ]]; then
            rm -f "${outdir}/subzy.txt"
            warn "subzy — no vulnerable subdomains found, file not saved"
        else
            success "subzy done — ${BOLD}${count} vulnerable subdomains${RESET} → ${outdir}/subzy.txt"
        fi
    else
        warn "subzy not found, skipping"
    fi
}

run_dns_reaper() {
    section "DNS Takeover Check (dns-reaper)"
    if is_available "dns-reaper"; then
        info "Running dns-reaper on all subdomains..."
        dns-reaper file \
            --filename "${outdir}/all_subdomains.txt" \
            --out "${outdir}/dnsreaper.json" \
            --out-format json \
            2>/dev/null

        success "dns-reaper done → ${outdir}/dnsreaper.json"
    else
        warn "dns-reaper not found, skipping"
    fi
}

print_summary() {
    section "Summary"
    echo -e "  ${BOLD}Target:${RESET}  ${MAGENTA}$target${RESET}"
    echo -e "  ${BOLD}Output:${RESET}  $outdir"
    echo ""
    echo -e "  ${BOLD}Enumeration files:${RESET}"
    for f in subfinder assetfinder amass github-subdomains; do
        local path="${outdir}/${f}.txt"
        printf "    %-42s %s lines\n" "$path" "$(count_lines "$path")"
    done
    echo ""
    printf "    %-42s %s unique subdomains\n" "${outdir}/all_subdomains.txt" "$(count_lines "${outdir}/all_subdomains.txt")"
    printf "    %-42s %s live hosts\n"        "${outdir}/live_hosts.txt"     "$(count_lines "${outdir}/live_hosts.txt")"
    printf "    %-42s %s URLs crawled\n"      "${outdir}/katana.txt"         "$(count_lines "${outdir}/katana.txt")"
    printf "    %-42s %s findings\n"          "${outdir}/trufflehog.txt"     "$(count_lines "${outdir}/trufflehog.txt")"
    printf "    %-42s %s findings\n"          "${outdir}/betterleaks.txt"    "$(count_lines "${outdir}/betterleaks.txt")"
    printf "    %-42s %s results\n"           "${outdir}/subzy.txt"          "$(count_lines "${outdir}/subzy.txt")"
    echo ""
}

# ── Entry point ───────────────────────────────────────────────────────────────
banner
echo -e "${BOLD}Target:${RESET}  ${MAGENTA}$target${RESET}"
echo -e "${BOLD}Output:${RESET}  $outdir"
echo -e "${BOLD}Rate:${RESET}    ${rl} rps / ${rlm} rpm — threads: ${threads}"
echo -e "${DIM}Started: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"

checktools
run_tools
merge_output
run_httpx
run_katana
run_trufflehog
run_betterleaks
run_subzy
run_dns_reaper
print_summary

