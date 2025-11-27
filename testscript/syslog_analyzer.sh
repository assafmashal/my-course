#!/bin/bash

#############################################
# Syslog Analyzer Script
# Analyzes syslog for IP addresses with errors/warnings
# Author: DevOps Script
# Date: $(date +%Y-%m-%d)
#############################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default syslog path
SYSLOG_PATH="/var/log/syslog"

# Check if alternative path provided
if [ ! -z "$1" ]; then
    SYSLOG_PATH="$1"
fi

# Check if syslog file exists
if [ ! -f "$SYSLOG_PATH" ]; then
    echo -e "${RED}Error: Syslog file not found at $SYSLOG_PATH${NC}"
    echo "Usage: $0 [path_to_syslog]"
    exit 1
fi

# Create reports directory if it doesn't exist
REPORT_DIR="./syslog_reports"
mkdir -p "$REPORT_DIR"

# Generate timestamped report filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/syslog_analysis_$TIMESTAMP.txt"

# Define error/warning keywords
KEYWORDS=(
    "error"
    "ERROR"
    "Error"
    "fail"
    "failed"
    "FAILED"
    "failure"
    "warning"
    "WARNING"
    "warn"
    "WARN"
    "critical"
    "CRITICAL"
    "alert"
    "ALERT"
    "emergency"
    "panic"
    "denied"
    "DENIED"
    "refused"
    "timeout"
    "TIMEOUT"
    "unreachable"
    "down"
    "unable"
    "cannot"
    "fatal"
    "FATAL"
)

# Temporary files
TEMP_IP_LINES="/tmp/syslog_ip_lines_$$.txt"
TEMP_ANALYSIS="/tmp/syslog_analysis_$$.txt"

# Cleanup function
cleanup() {
    rm -f "$TEMP_IP_LINES" "$TEMP_ANALYSIS"
}

trap cleanup EXIT

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Syslog Analysis Tool${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Analyzing: ${GREEN}$SYSLOG_PATH${NC}"
echo -e "Report will be saved to: ${GREEN}$REPORT_FILE${NC}"
echo ""

# Extract lines containing IP addresses
# IPv4 pattern: matches xxx.xxx.xxx.xxx
echo -e "${YELLOW}[1/4] Extracting lines with IP addresses...${NC}"
grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' "$SYSLOG_PATH" > "$TEMP_IP_LINES"

IP_LINE_COUNT=$(wc -l < "$TEMP_IP_LINES")
echo -e "      Found ${GREEN}$IP_LINE_COUNT${NC} lines with IP addresses"

if [ $IP_LINE_COUNT -eq 0 ]; then
    echo -e "${RED}No IP addresses found in syslog. Exiting.${NC}"
    exit 0
fi

# Filter lines containing keywords
echo -e "${YELLOW}[2/4] Filtering for error/warning keywords...${NC}"

# Build grep pattern from keywords
KEYWORD_PATTERN=$(IFS='|'; echo "${KEYWORDS[*]}")

grep -E "$KEYWORD_PATTERN" "$TEMP_IP_LINES" > "$TEMP_ANALYSIS"

FILTERED_COUNT=$(wc -l < "$TEMP_ANALYSIS")
echo -e "      Found ${GREEN}$FILTERED_COUNT${NC} lines with error/warning keywords"

if [ $FILTERED_COUNT -eq 0 ]; then
    echo -e "${YELLOW}No error/warning keywords found in IP-containing lines.${NC}"
    exit 0
fi

# Extract and count IPs
echo -e "${YELLOW}[3/4] Analyzing IP addresses and keywords...${NC}"

# Create associative arrays (requires bash 4+)
declare -A IP_COUNT
declare -A IP_KEYWORDS

# Process each line
while IFS= read -r line; do
    # Extract all IP addresses from the line
    IPS=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
    
    # Check which keywords appear in the line
    FOUND_KEYWORDS=""
    for keyword in "${KEYWORDS[@]}"; do
        if echo "$line" | grep -qi "$keyword"; then
            if [ -z "$FOUND_KEYWORDS" ]; then
                FOUND_KEYWORDS="$keyword"
            else
                FOUND_KEYWORDS="$FOUND_KEYWORDS, $keyword"
            fi
        fi
    done
    
    # Update counts and keywords for each IP
    for ip in $IPS; do
        ((IP_COUNT[$ip]++))
        
        # Add keywords to IP's keyword list (avoid duplicates)
        if [ -z "${IP_KEYWORDS[$ip]}" ]; then
            IP_KEYWORDS[$ip]="$FOUND_KEYWORDS"
        else
            # Add new keywords if not already present
            for kw in $(echo "$FOUND_KEYWORDS" | tr ',' '\n'); do
                kw=$(echo "$kw" | xargs) # trim whitespace
                if ! echo "${IP_KEYWORDS[$ip]}" | grep -q "$kw"; then
                    IP_KEYWORDS[$ip]="${IP_KEYWORDS[$ip]}, $kw"
                fi
            done
        fi
    done
done < "$TEMP_ANALYSIS"

# Generate report
echo -e "${YELLOW}[4/4] Generating report...${NC}"

{
    echo "=========================================="
    echo "      SYSLOG ANALYSIS REPORT"
    echo "=========================================="
    echo ""
    echo "Analysis Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Syslog File: $SYSLOG_PATH"
    echo "Report Generated: $REPORT_FILE"
    echo ""
    echo "=========================================="
    echo "      SUMMARY"
    echo "=========================================="
    echo ""
    echo "Total lines with IP addresses: $IP_LINE_COUNT"
    echo "Lines with error/warning keywords: $FILTERED_COUNT"
    echo "Unique IP addresses with issues: ${#IP_COUNT[@]}"
    echo ""
    echo "Keywords monitored:"
    for keyword in "${KEYWORDS[@]}"; do
        echo "  - $keyword"
    done
    echo ""
    echo "=========================================="
    echo "      DETAILED IP ANALYSIS"
    echo "=========================================="
    echo ""
    
    # Sort IPs by count (descending)
    for ip in "${!IP_COUNT[@]}"; do
        echo "${IP_COUNT[$ip]} $ip"
    done | sort -rn | while read count ip; do
        echo "IP Address: $ip"
        echo "  Occurrences: $count"
        echo "  Keywords found: ${IP_KEYWORDS[$ip]}"
        echo ""
        echo "  Sample log entries:"
        grep "$ip" "$TEMP_ANALYSIS" | head -3 | while IFS= read -r sample_line; do
            echo "    $sample_line"
        done
        echo ""
        echo "----------------------------------------"
        echo ""
    done
    
    echo "=========================================="
    echo "      TOP 10 PROBLEMATIC IPs"
    echo "=========================================="
    echo ""
    printf "%-4s %-15s %-10s %s\n" "Rank" "IP Address" "Count" "Keywords"
    echo "------------------------------------------------------------"
    
    rank=1
    for ip in "${!IP_COUNT[@]}"; do
        echo "${IP_COUNT[$ip]} $ip"
    done | sort -rn | head -10 | while read count ip; do
        keywords_short=$(echo "${IP_KEYWORDS[$ip]}" | cut -c 1-40)
        printf "%-4s %-15s %-10s %s\n" "$rank" "$ip" "$count" "$keywords_short"
        ((rank++))
    done
    
    echo ""
    echo "=========================================="
    echo "      END OF REPORT"
    echo "=========================================="
    
} > "$REPORT_FILE"

# Display the report
echo ""
echo -e "${GREEN}✓ Analysis complete!${NC}"
echo ""
cat "$REPORT_FILE"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "Report saved to: ${GREEN}$REPORT_FILE${NC}"
echo -e "${BLUE}========================================${NC}"