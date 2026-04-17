#!/bin/bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST_DIR="$BASE_DIR/Wordlists/webdiscovery"
SELECTED_WORDLIST=""

# COLORS
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# ═══════════════════════════════════════
# BANNER
# ═══════════════════════════════════════
print_banner() {
    clear
    echo -e "${RED}"
    echo " ████████████████████████████████████████████████████████"
    echo " █ ${CYAN}H4CK3R N3T SC4NN3R${RED} v3.0                         █"
    echo " █ ${PURPLE}CTF Recon Framework${RED}                          █"
    echo " ████████████████████████████████████████████████████████"
    echo -e "${NC}"
}

# ═══════════════════════════════════════
# INPUT
# ═══════════════════════════════════════
get_user_input() {
    echo -e "${BLUE}[?] Target network (X.X.X.X/24): ${NC}"
    read -r TARGET

    if [[ ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]{1,2}$ ]]; then
        echo -e "${RED}[-] Invalid CIDR${NC}"
        exit 1
    fi

    echo -e "${BLUE}[?] Scan name: ${NC}"
    read -r SCAN_NAME

    [[ -z "$SCAN_NAME" ]] && SCAN_NAME="scan"

    OUTPUT_DIR="${SCAN_NAME}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"

    echo -e "${GREEN}[+] Output: $OUTPUT_DIR${NC}"
}

# ═══════════════════════════════════════
# PING SCAN
# ═══════════════════════════════════════
run_ping_scan() {
    echo -e "${PURPLE}[*] Running ping sweep...${NC}"

    sudo nmap -sn -n -PE "$TARGET" \
        -oA "${OUTPUT_DIR}/ping_scan"

    echo -e "${GREEN}[+] Done${NC}"
}

# ═══════════════════════════════════════
# EXTRACT IPS
# ═══════════════════════════════════════
extract_live_hosts() {
    echo -e "${CYAN}[*] Extracting live hosts...${NC}"

    grep -ia 'Status: Up' "${OUTPUT_DIR}/ping_scan.gnmap" \
        | cut -d ' ' -f 2 \
        | sort -u > "${OUTPUT_DIR}/ipup.txt"

    echo -e "${GREEN}[+] $(wc -l < "${OUTPUT_DIR}/ipup.txt") hosts found${NC}"
}

# ═══════════════════════════════════════
# TCP SCAN
# ═══════════════════════════════════════
deep_tcp_scan() {
    echo -e "${PURPLE}[*] Deep scanning hosts...${NC}"

    while IFS= read -r IP; do
        echo -e "${BLUE}[*] $IP${NC}"

        IP_DIR="${OUTPUT_DIR}/host_${IP//./_}"
        mkdir -p "$IP_DIR"

        sudo nmap -sV -sC -T4 "$IP" \
            -oN "${IP_DIR}/scan.txt" \
            -oG "${IP_DIR}/scan.gnmap" \
            -oX "${IP_DIR}/scan.xml"

    done < "${OUTPUT_DIR}/ipup.txt"

    echo -e "${GREEN}[+] All scans complete${NC}"
}

# ═══════════════════════════════════════
# SHOW NMAP
# ═══════════════════════════════════════
show_nmap() {
    local DIR="$1"

    if [[ -f "$DIR/scan.txt" ]]; then
        less "$DIR/scan.txt"
    else
        echo "No scan file"
    fi
}

# ═══════════════════════════════════════
# CVE CHECK
# ═══════════════════════════════════════
cve_scan() {
    local DIR="$1"

    while true; do
        echo -e "${YELLOW}[*] CVE / Exploit Options${NC}"
        echo "1) Run searchsploit (parsed)"
        echo "2) Show raw Nmap services"
        echo "3) Back"

        read -rp "Choice: " opt

        case $opt in
            1)
                run_searchsploit "$DIR"
                ;;
            2)
                grep -E "open" "$DIR/scan.txt"
                ;;
            3)
                return
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
    done
}
# ═══════════════════════════════════════
# SEARCHSPLOIT
# ═══════════════════════════════════════
run_searchsploit() {
    local DIR="$1"

    echo -e "${CYAN}[*] Searching exploits...${NC}"

    grep "open" "$DIR/scan.txt" | while read -r line; do

        SERVICE=$(echo "$line" | awk '{print $3}')
        VERSION=$(echo "$line" | cut -d ' ' -f 4-)

        [[ -z "$SERVICE" ]] && continue

        echo -e "\n${PURPLE}[+] $SERVICE $VERSION${NC}"

        # 🔥 WICHTIG: kein set -e crash durch grep
        searchsploit "$SERVICE $VERSION" 2>/dev/null \
            | grep -Ei "exploit|remote|rce" || true \
            | head -5

    done
}
# ═══════════════════════════════════════
# WORDLIST SELECT
# ═══════════════════════════════════════
choose_wordlist() {
    local WORDLISTS=()

    mapfile -t WORDLISTS < <(find "$WORDLIST_DIR" -type f -name "*.txt" | sort)

    if [[ ${#WORDLISTS[@]} -eq 0 ]]; then
        echo "No wordlists found"
        return 1
    fi

    echo -e "\nSelect web wordlist:"

    select WL in "${WORDLISTS[@]}" "Back"; do
        if [[ "$WL" == "Back" ]]; then
            return 1
        elif [[ -n "$WL" ]]; then
            SELECTED_WORDLIST="$WL"
            return 0
        else
            echo "Invalid selection"
        fi
    done
}
# --------------------------------------
# WEB TARGET
# --------------------------------------
choose_web_target() {
    local IP="$1"

    while true; do
        echo -e "\n${CYAN}Select protocol:${NC}"
        echo "1) http (80)"
        echo "2) https (443)"
        echo "3) custom port"
        echo "4) Back"

        read -rp "Choice: " opt

        case $opt in
            1)
                WEB_URL="http://$IP"
                return 0
                ;;
            2)
                WEB_URL="https://$IP"
                return 0
                ;;
            3)
                read -rp "Enter port: " PORT

                # einfache Validierung
                if [[ "$PORT" =~ ^[0-9]+$ ]]; then
                    echo "1) http"
                    echo "2) https"
                    read -rp "Protocol: " proto

                    if [[ "$proto" == "1" ]]; then
                        WEB_URL="http://$IP:$PORT"
                    elif [[ "$proto" == "2" ]]; then
                        WEB_URL="https://$IP:$PORT"
                    else
                        echo "Invalid protocol"
                        continue
                    fi

                    return 0
                else
                    echo "Invalid port"
                fi
                ;;
            4)
                return 1
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
    done
}


# ═══════════════════════════════════════
# WEB SCAN
# ═══════════════════════════════════════
web_scan() {
    local IP="$1"
    local DIR="$2"

    if ! grep -qi "http" "$DIR/scan.txt"; then
        echo "No HTTP service detected"
        return
    fi

    choose_wordlist || return
    WORDLIST="$SELECTED_WORDLIST"

    choose_web_target "$IP" || return
    URL="$WEB_URL"

    echo -e "${GREEN}[+] Target: $URL${NC}"
    echo -e "${GREEN}[+] Wordlist: $WORDLIST${NC}"

    if [[ ! -f "$WORDLIST" ]]; then
        echo -e "${RED}[-] Invalid wordlist${NC}"
        return
    fi

    echo -e "${YELLOW}[*] Running feroxbuster...${NC}"

    feroxbuster \
        -u "$URL" \
        -w "$WORDLIST" \
	-k \
        -o "${DIR}/dirscan.txt"
}
# ═══════════════════════════════════════
# HOST MENU
# ═══════════════════════════════════════
host_menu() {
    local IP="$1"
    local DIR="${OUTPUT_DIR}/host_${IP//./_}"

    while true; do
        echo -e "\n${PURPLE}=== Host: $IP ===${NC}"
        echo "1) Show Nmap Results"
        echo "2) CVE Scan"
        echo "3) Web Scan"
        echo "4) Back"

        read -rp "Choice: " choice

        case $choice in
            1) show_nmap "$DIR" ;;
            2) cve_scan "$DIR" ;;
            3) web_scan "$IP" "$DIR" ;;
            4) break ;;
            *) echo "Invalid" ;;
        esac
    done
}

# ═══════════════════════════════════════
# IP MENU
# ═══════════════════════════════════════
select_ip() {
    mapfile -t IPS < "${OUTPUT_DIR}/ipup.txt"

    echo -e "${CYAN}=== Select Host ===${NC}"

    select IP in "${IPS[@]}" "Exit"; do
        if [[ "$IP" == "Exit" ]]; then
            break
        elif [[ -n "$IP" ]]; then
            host_menu "$IP"
        else
            echo "Invalid"
        fi
    done
}

# ═══════════════════════════════════════
# MAIN
# ═══════════════════════════════════════
main() {
    print_banner
    get_user_input

    echo -e "\n${CYAN}═══ PHASE 1: PING ═══${NC}"
    run_ping_scan

    echo -e "\n${CYAN}═══ PHASE 2: HOSTS ═══${NC}"
    extract_live_hosts

    echo -e "\n${CYAN}═══ PHASE 3: TCP ═══${NC}"
    deep_tcp_scan

    echo -e "\n${GREEN}🎉 Scan Complete${NC}"

    echo -e "\n${CYAN}═══ INTERACTIVE MODE ═══${NC}"
    select_ip
}

main
