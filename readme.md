# Syslog Analyzer Script

## Overview
A bash script that analyzes syslog files to identify IP addresses associated with errors and warnings. The script extracts lines containing IP addresses, filters them for error/warning keywords, and generates a comprehensive timestamped report.

## Features

✓ **IP Address Detection**: Extracts all lines containing IPv4 addresses
✓ **Keyword Filtering**: Searches for 28 different error/warning keywords
✓ **Frequency Analysis**: Counts occurrences per IP address
✓ **Keyword Tracking**: Collects all keywords found for each IP
✓ **Timestamped Reports**: Saves analysis in timestamped files
✓ **Color Output**: Visual feedback during analysis
✓ **Top 10 Ranking**: Shows most problematic IPs

## Keywords Monitored

The script monitors the following keywords (case-insensitive):
- error, ERROR, Error
- fail, failed, FAILED, failure
- warning, WARNING, warn, WARN
- critical, CRITICAL
- alert, ALERT
- emergency, panic
- denied, DENIED, refused
- timeout, TIMEOUT
- unreachable, down
- unable, cannot
- fatal, FATAL

## Usage

### Basic Usage
```bash
./syslog_analyzer.sh [path_to_syslog]
```

### Examples

**Analyze default syslog:**
```bash
./syslog_analyzer.sh /var/log/syslog
```

**Analyze custom log file:**
```bash
./syslog_analyzer.sh /var/log/auth.log
```

**Test with sample data:**
```bash
./syslog_analyzer.sh sample_syslog.txt
```

## Output

### Console Output
The script provides real-time feedback:
1. File being analyzed
2. Number of lines with IP addresses
3. Number of lines with error/warning keywords
4. Full report display

### Report File
Reports are saved in `./syslog_reports/` with the format:
```
syslog_analysis_YYYYMMDD_HHMMSS.txt
```

### Report Contents
Each report includes:
- **Summary**: Total counts and statistics
- **Detailed IP Analysis**: Per-IP breakdown with sample log entries
- **Top 10 Problematic IPs**: Ranked by occurrence count

## Requirements

- **Bash**: Version 4.0+ (for associative arrays)
- **Permissions**: Read access to syslog files
- **Tools**: grep, awk, sort (standard Linux utilities)

## Installation

1. **Download the script:**
   ```bash
   curl -O https://your-repo/syslog_analyzer.sh
   ```

2. **Make it executable:**
   ```bash
   chmod +x syslog_analyzer.sh
   ```

3. **Run the script:**
   ```bash
   ./syslog_analyzer.sh /var/log/syslog
   ```

## Permissions

For analyzing system logs, you may need sudo:
```bash
sudo ./syslog_analyzer.sh /var/log/syslog
```

Or add your user to the appropriate group:
```bash
sudo usermod -a -G adm $USER
```

## Sample Output

```
========================================
   Syslog Analysis Tool
========================================
Analyzing: /var/log/syslog
Report will be saved to: ./syslog_reports/syslog_analysis_20251127_154629.txt

[1/4] Extracting lines with IP addresses...
      Found 22 lines with IP addresses
[2/4] Filtering for error/warning keywords...
      Found 12 lines with error/warning keywords
[3/4] Analyzing IP addresses and keywords...
[4/4] Generating report...

✓ Analysis complete!
```

## Report Example

```
==========================================
      DETAILED IP ANALYSIS
==========================================

IP Address: 10.0.0.50
  Occurrences: 7
  Keywords found: error, failed, refused, denied
  
  Sample log entries:
    Nov 27 10:16:10 webserver nginx: [error] connect() failed
    Nov 27 10:22:00 webserver apache2: Permission denied
    Nov 27 10:30:00 dns named: query denied

==========================================
      TOP 10 PROBLEMATIC IPs
==========================================

Rank IP Address      Count      Keywords
------------------------------------------------------------
1    10.0.0.50       7          error, failed, refused, denied
2    203.0.113.25    2          warning, warn
3    198.51.100.75   2          error, failed, denied
```

## Customization

### Adding Keywords
Edit the `KEYWORDS` array in the script:
```bash
KEYWORDS=(
    "your_keyword"
    "another_keyword"
    # ... existing keywords
)
```

### Changing Report Location
Modify the `REPORT_DIR` variable:
```bash
REPORT_DIR="/path/to/your/reports"
```

### Adjusting Sample Log Entries
Change the `head -3` value in the sample entries section:
```bash
grep "$ip" "$TEMP_ANALYSIS" | head -5  # Shows 5 entries instead of 3
```

## Troubleshooting

**No IP addresses found:**
- Check if the log file contains valid IPv4 addresses
- Verify file path is correct

**Permission denied:**
- Use sudo to run the script
- Check file permissions: `ls -l /var/log/syslog`

**Script not executable:**
- Run: `chmod +x syslog_analyzer.sh`

## Use Cases

- **Security Monitoring**: Identify IPs with failed authentication attempts
- **Network Troubleshooting**: Find connection failures and timeouts
- **System Administration**: Track recurring errors from specific hosts
- **Compliance**: Document security events with timestamps
- **Incident Response**: Quick analysis of problematic IP addresses

## Limitations

- Only detects IPv4 addresses (not IPv6)
- Requires Bash 4.0+ for associative arrays
- Cannot analyze compressed log files directly (decompress first)

## Author

DevOps Training Script
Date: 2025-11-27

## License

Free to use and modify for educational and professional purposes.
