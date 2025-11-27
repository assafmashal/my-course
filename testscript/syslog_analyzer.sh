#!/bin/bash

#############################################
# Syslog Analyzer Script - Refactored Version
# Analyzes syslog for IP addresses with errors/warnings
# Author: DevOps Script
# Date: 2025-11-27
# Version: 2.0
#############################################

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# Enable debug mode if DEBUG environment variable is set
[[ "${DEBUG:-0}" == "1" ]] && set -x

#############################################
# GLOBAL VARIABLES
#############################################

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_DIR="${REPORT_DIR:-./syslog_reports}"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly REPORT_FILE="${REPORT_DIR}/syslog_analysis_${TIMESTAMP}.txt"

# IPv4 regex pattern
readonly IPV4_PATTERN='([0-9]{1,3}\.){3}[0-9]{1,3}'

# Error/warning keywords
readonly KEYWORDS=(
    "error" "ERROR" "Error"
    "fail" "failed" "FAILED" "failure"
    "warning" "WARNING" "warn" "WARN"
    "critical" "CRITICAL"
    "alert" "ALERT"
    "emergency" "panic"
    "denied" "DENIED" "refused"
    "timeout" "TIMEOUT"
    "unreachable" "down"
    "unable" "cannot"
    "fatal" "FATAL"
)

# Temporary files
readonly TEMP_DIR="/tmp/${SCRIPT_NAME}_$$"
readonly TEMP_IP_LINES="${TEMP_DIR}/ip_lines.txt"
readonly TEMP_ANALYSIS="${TEMP_DIR}/analysis.txt"

# Associative arrays (requires Bash 4.0+)
declare -A IP_COUNT
declare -A IP_KEYWORDS

# Statistics
TOTAL_IP_LINES=0
TOTAL_FILTERED_LINES=0

#############################################
# UTILITY FUNCTIONS
#############################################

# Print colored messages
print_error() {
    echo -e "${RED}ERROR: $*${NC}" >&2
}

print_success() {
    echo -e "${GREEN}✓ $*${NC}"
}

print_warning() {
    echo -e "${YELLOW}WARNING: $*${NC}" >&2
}

print_info() {
    echo -e "${BLUE}$*${NC}"
}

print_step() {
    echo -e "${YELLOW}$*${NC}"
}

# Print header
print_header() {
    local title="$1"
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${BLUE}   ${title}${NC}"
    echo -e "${BLUE}==========================================${NC}"
}

#############################################
# ERROR HANDLING
#############################################

# Cleanup function
cleanup() {
    local exit_code=$?
    
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
    
    if [[ ${exit_code} -ne 0 ]]; then
        print_error "Script exited with error code ${exit_code}"
    fi
    
    exit "${exit_code}"
}

# Error handler
error_handler() {
    local line_no=$1
    local exit_code=$2
    print_error "Error occurred in script at line ${line_no} with exit code ${exit_code}"
}

# Set traps
trap cleanup EXIT
trap 'error_handler ${LINENO} $?' ERR

#############################################
# VALIDATION FUNCTIONS
#############################################

# Check Bash version
check_bash_version() {
    local required_version=4
    local current_version="${BASH_VERSINFO[0]}"
    
    if (( current_version < required_version )); then
        print_error "Bash version ${required_version}.0+ required. Current version: ${BASH_VERSION}"
        return 1
    fi
}

# Validate file exists and is readable
validate_file() {
    local file="$1"
    
    if [[ ! -f "${file}" ]]; then
        print_error "File not found: ${file}"
        return 1
    fi
    
    if [[ ! -r "${file}" ]]; then
        print_error "File not readable: ${file}"
        return 1
    fi
    
    return 0
}

# Check required commands
check_dependencies() {
    local missing_deps=()
    local required_commands=("grep" "awk" "sort" "wc" "date")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "${cmd}" &> /dev/null; then
            missing_deps+=("${cmd}")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required commands: ${missing_deps[*]}"
        return 1
    fi
}

#############################################
# INITIALIZATION FUNCTIONS
#############################################

# Setup environment
setup_environment() {
    # Create temporary directory
    mkdir -p "${TEMP_DIR}"
    
    # Create report directory
    mkdir -p "${REPORT_DIR}"
    
    # Touch temp files
    touch "${TEMP_IP_LINES}" "${TEMP_ANALYSIS}"
}

# Display usage
usage() {
    cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS] <logfile>

Analyze syslog files for IP addresses with errors and warnings.

OPTIONS:
    -h, --help          Show this help message
    -o, --output DIR    Specify output directory (default: ./syslog_reports)
    -v, --verbose       Enable verbose output
    -d, --debug         Enable debug mode

ARGUMENTS:
    <logfile>           Path to the log file to analyze

EXAMPLES:
    ${SCRIPT_NAME} /var/log/syslog
    ${SCRIPT_NAME} -o /tmp/reports sample_syslog.txt
    DEBUG=1 ${SCRIPT_NAME} /var/log/auth.log

EOF
}

# Parse command line arguments
parse_arguments() {
    local syslog_path=""
    
    # Handle no arguments case
    if [[ $# -eq 0 ]]; then
        echo ""
        return
    fi
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                echo "SHOW_HELP"
                return
                ;;
            -o|--output)
                if [[ -z "${2:-}" ]]; then
                    print_error "Option -o requires an argument"
                    echo "ERROR"
                    return
                fi
                REPORT_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            -d|--debug)
                set -x
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                echo "ERROR"
                return
                ;;
            *)
                syslog_path="$1"
                shift
                ;;
        esac
    done
    
    # Return the log file path
    echo "${syslog_path}"
}

#############################################
# ANALYSIS FUNCTIONS
#############################################

# Extract lines containing IP addresses
extract_ip_lines() {
    local logfile="$1"
    
    print_step "[1/4] Extracting lines with IP addresses..."
    
    if ! grep -E "${IPV4_PATTERN}" "${logfile}" > "${TEMP_IP_LINES}" 2>/dev/null; then
        # grep returns non-zero if no matches, handle gracefully
        touch "${TEMP_IP_LINES}"
    fi
    
    TOTAL_IP_LINES=$(wc -l < "${TEMP_IP_LINES}")
    echo "      Found ${GREEN}${TOTAL_IP_LINES}${NC} lines with IP addresses"
    
    if [[ ${TOTAL_IP_LINES} -eq 0 ]]; then
        print_warning "No IP addresses found in log file"
        return 1
    fi
    
    return 0
}

# Build keyword pattern for grep
build_keyword_pattern() {
    local IFS='|'
    echo "${KEYWORDS[*]}"
}

# Filter lines for error/warning keywords
filter_keywords() {
    print_step "[2/4] Filtering for error/warning keywords..."
    
    local keyword_pattern
    keyword_pattern=$(build_keyword_pattern)
    
    if ! grep -E "${keyword_pattern}" "${TEMP_IP_LINES}" > "${TEMP_ANALYSIS}" 2>/dev/null; then
        touch "${TEMP_ANALYSIS}"
    fi
    
    TOTAL_FILTERED_LINES=$(wc -l < "${TEMP_ANALYSIS}")
    echo "      Found ${GREEN}${TOTAL_FILTERED_LINES}${NC} lines with error/warning keywords"
    
    if [[ ${TOTAL_FILTERED_LINES} -eq 0 ]]; then
        print_warning "No error/warning keywords found in IP-containing lines"
        return 1
    fi
    
    return 0
}

# Extract all IPs from a line
extract_ips_from_line() {
    local line="$1"
    grep -oE "${IPV4_PATTERN}" <<< "${line}" || true
}

# Find keywords in a line
find_keywords_in_line() {
    local line="$1"
    local found_keywords=()
    
    for keyword in "${KEYWORDS[@]}"; do
        if grep -qi "${keyword}" <<< "${line}"; then
            found_keywords+=("${keyword}")
        fi
    done
    
    # Join array with comma separator
    local IFS=','
    echo "${found_keywords[*]}"
}

# Check if keyword exists in list
keyword_exists() {
    local keyword="$1"
    local keyword_list="$2"
    
    grep -q "${keyword}" <<< "${keyword_list}"
}

# Add keywords to IP's keyword list (avoiding duplicates)
add_keywords_to_ip() {
    local ip="$1"
    local new_keywords="$2"
    
    if [[ -z "${IP_KEYWORDS[$ip]:-}" ]]; then
        IP_KEYWORDS[$ip]="${new_keywords}"
    else
        # Split new keywords and add if not present
        IFS=',' read -ra kw_array <<< "${new_keywords}"
        for kw in "${kw_array[@]}"; do
            kw=$(echo "${kw}" | xargs)  # trim whitespace
            if [[ -n "${kw}" ]] && ! keyword_exists "${kw}" "${IP_KEYWORDS[$ip]}"; then
                IP_KEYWORDS[$ip]="${IP_KEYWORDS[$ip]},${kw}"
            fi
        done
    fi
}

# Process log lines and count IPs/keywords
process_log_lines() {
    print_step "[3/4] Analyzing IP addresses and keywords..."
    
    local line ips found_keywords
    
    while IFS= read -r line; do
        # Extract all IP addresses from the line
        ips=$(extract_ips_from_line "${line}")
        
        # Find keywords in the line
        found_keywords=$(find_keywords_in_line "${line}")
        
        # Update counts and keywords for each IP
        for ip in ${ips}; do
            # Increment counter (handle unset variable with set -u)
            IP_COUNT[$ip]=$((${IP_COUNT[$ip]:-0} + 1))
            
            # Add keywords
            if [[ -n "${found_keywords}" ]]; then
                add_keywords_to_ip "${ip}" "${found_keywords}"
            fi
        done
    done < "${TEMP_ANALYSIS}"
}

#############################################
# REPORT GENERATION FUNCTIONS
#############################################

# Generate report header
generate_report_header() {
    local logfile="$1"
    cat << EOF
==========================================
      SYSLOG ANALYSIS REPORT
==========================================

Analysis Date: $(date '+%Y-%m-%d %H:%M:%S')
Syslog File: ${logfile}
Report Generated: ${REPORT_FILE}

==========================================
      SUMMARY
==========================================

Total lines with IP addresses: ${TOTAL_IP_LINES}
Lines with error/warning keywords: ${TOTAL_FILTERED_LINES}
Unique IP addresses with issues: ${#IP_COUNT[@]}

Keywords monitored:
EOF

    for keyword in "${KEYWORDS[@]}"; do
        echo "  - ${keyword}"
    done
}

# Get sample log entries for an IP
get_sample_entries() {
    local ip="$1"
    local max_samples="${2:-3}"
    
    grep "${ip}" "${TEMP_ANALYSIS}" | head -n "${max_samples}" | while IFS= read -r sample_line; do
        echo "    ${sample_line}"
    done
}

# Generate detailed IP analysis section
generate_detailed_analysis() {
    cat << EOF

==========================================
      DETAILED IP ANALYSIS
==========================================

EOF

    # Sort IPs by count (descending) and process
    # Check if array has elements first
    if [[ ${#IP_COUNT[@]} -gt 0 ]]; then
        for ip in "${!IP_COUNT[@]}"; do
            echo "${IP_COUNT[$ip]} ${ip}"
        done | sort -rn | while read -r count ip; do
        cat << EOF
IP Address: ${ip}
  Occurrences: ${count}
  Keywords found: ${IP_KEYWORDS[$ip]}

  Sample log entries:
EOF
        get_sample_entries "${ip}" 3
        echo ""
        echo "----------------------------------------"
        echo ""
    done
    fi
}

# Generate top 10 table
generate_top10_table() {
    cat << EOF

==========================================
      TOP 10 PROBLEMATIC IPs
==========================================

EOF

    printf "%-4s %-15s %-10s %s\n" "Rank" "IP Address" "Count" "Keywords"
    echo "------------------------------------------------------------"
    
    if [[ ${#IP_COUNT[@]} -gt 0 ]]; then
        local rank=1
        for ip in "${!IP_COUNT[@]}"; do
            echo "${IP_COUNT[$ip]} ${ip}"
        done | sort -rn | head -10 | while read -r count ip; do
            local keywords_short="${IP_KEYWORDS[$ip]:0:40}"
            printf "%-4s %-15s %-10s %s\n" "${rank}" "${ip}" "${count}" "${keywords_short}"
            ((rank++)) || true
        done
    fi
}

# Generate report footer
generate_report_footer() {
    cat << EOF

==========================================
      END OF REPORT
==========================================
EOF
}

# Generate complete report
generate_report() {
    local logfile="$1"
    print_step "[4/4] Generating report..."
    
    {
        generate_report_header "${logfile}"
        generate_detailed_analysis
        generate_top10_table
        generate_report_footer
    } > "${REPORT_FILE}"
}

# Display report to console
display_report() {
    echo ""
    print_success "Analysis complete!"
    echo ""
    cat "${REPORT_FILE}"
    echo ""
    print_header "Report saved to: ${REPORT_FILE}"
}

#############################################
# MAIN FUNCTION
#############################################

main() {
    local syslog_path
    
    # Check bash version first
    check_bash_version || exit 1
    
    # Check dependencies
    check_dependencies || exit 1
    
    # Parse arguments
    syslog_path=$(parse_arguments "$@")
    
    # Handle special return values
    if [[ "${syslog_path}" == "SHOW_HELP" ]]; then
        usage
        exit 0
    elif [[ "${syslog_path}" == "ERROR" ]]; then
        usage
        exit 1
    elif [[ -z "${syslog_path}" ]]; then
        print_error "No log file specified"
        usage
        exit 1
    fi
    
    # Validate file
    validate_file "${syslog_path}" || exit 1
    
    # Setup environment
    setup_environment
    
    # Display header
    print_header "Syslog Analysis Tool"
    echo -e "Analyzing: ${GREEN}${syslog_path}${NC}"
    echo -e "Report will be saved to: ${GREEN}${REPORT_FILE}${NC}"
    echo ""
    
    # Run analysis pipeline
    if ! extract_ip_lines "${syslog_path}"; then
        exit 0
    fi
    
    if ! filter_keywords; then
        exit 0
    fi
    
    process_log_lines
    generate_report "${syslog_path}"
    display_report
}

#############################################
# SCRIPT ENTRY POINT
#############################################

# Only run main if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi