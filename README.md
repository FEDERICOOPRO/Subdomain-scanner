# Python Subdomain Analyzer Script

A Python script to analyze a list of subdomains from a CSV file. It checks their reachability (HTTP/S status), categorizes them, identifies potentially sensitive subdomains based on keywords, and supports graceful shutdown with partial results output.

## ⚠️⚠️⚠️ **Use Responsibly**

This tool is provided strictly for **educational purposes** and **authorized security testing** only.  
Do **not** use this script on targets for which you do not have **explicit permission**.

By using this tool, you acknowledge that:
- You are solely responsible for how it is used.
- Any **unauthorized scanning** or misuse may be **illegal** and is **strictly prohibited**.
- The author assumes **no liability** for damage or legal consequences resulting from its use.

Use it wisely, ethically, and within the bounds of the law.
 **Released under the MIT License**

## ⚠️⚠️⚠️

## Description

This script takes a CSV file containing subdomains (expecting the subdomain as the first value on each line) as input. For each subdomain, it performs the following actions:

1.  **DNS Resolution Check:** Attempts to resolve the subdomain to an IP address.
2.  **HTTP/S Reachability:** Tries to connect via HTTPS first, then falls back to HTTP if necessary. It records the final status (Working, Timeout, Connection Error, Not Resolving, etc.).
3.  **Keyword Analysis:** Checks if the subdomain name contains predefined keywords often associated with sensitive or interesting environments (e.g., `admin`, `dev`, `internal`, `api`).
4.  **Categorization:** Organizes the results into lists: Working, Not Working, Interrupted (if stopped early), and Potentially Sensitive.
5.  **Output:** Prints the categorized results to the console and optionally saves them to separate CSV files.
6.  **Concurrency:** Uses threading to perform checks concurrently for faster analysis.
7.  **Graceful Shutdown:** Allows the user to stop the script prematurely (using `Ctrl+C`) and still receive the results processed up to that point.

## Features

* Reads subdomains from a CSV file (extracts the first value before any comma).
* Checks status via DNS lookup and HTTP/S GET requests.
* Prioritizes HTTPS, falls back to HTTP on specific failures (Timeout, Connection Error, SSL Error).
* Identifies potentially sensitive subdomains using a configurable keyword list.
* Concurrent scanning using `ThreadPoolExecutor`.
* Configurable number of concurrent workers (`-w` / `--workers`).
* Configurable request timeout (`-t` / `--timeout`).
* Graceful shutdown on `Ctrl+C` with partial results output.
* Optional saving of categorized results to separate CSV files (`-o` / `--output`).
* Verbose logging option for debugging (`-v` / `--verbose`).

## Requirements

* Python 3.7+
* `requests` library

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/FEDERICOOPRO/Subdomain-scanner
    cd Subdomain-scanner
    ```

2.  **Install dependencies:**
    ```bash
    pip install requests
    ```

## Usage

```bash
python subdomain_analyzer.py <csv_file> [options]
```
##Input CSV Format:

The script expects a CSV file where each line contains the subdomain to be analyzed as the first value before the first comma. Any subsequent comma-separated values on the same line are ignored by this script.
Example subdomains.csv content:

[www.example.com](https://www.example.com),1.1.1.1,true
mail.example.com,2.2.2.2,false
dev.internal.example.com,10.0.0.1,true
admin.example.com,,
staging-app.example.com
nonexistent-domain.xyz,1.2.3.4,false

## Command-line Options:

```csv_file```: (Required) Path to the input CSV file.

```-o PREFIX```, ```--output PREFIX```: (Optional) Prefix for output CSV files (e.g., ```scan_results```). If provided, results will be saved to ```PREFIX_working.csv```, ```PREFIX_not_working.csv```, and ```PREFIX_potentially_sensitive.csv```.

```-w WORKERS```, ```--workers WORKERS```: (Optional) Number of concurrent workers (threads) to use. Default is 10.

```-t TIMEOUT```, ```--timeout TIMEOUT```: (Optional) Request timeout in seconds for HTTP/S checks. Default is 10.

```-v```, ```--verbose```: (Optional) Enable DEBUG level logging for more detailed output.

## Examples:

1. Basic analysis, print to console:
```
python subdomain_analyzer.py subdomains.csv
```
2. Analysis with saving results and fewer workers:
```
python subdomain_analyzer.py subdomains.csv -o my_scan_results -w 5
```
3. Analysis with verbose output and different timeout:
```
python subdomain_analyzer.py subdomains.csv -t 15 -v
```
## Stopping Early:

You can press Ctrl+C at any time while the script is running. It will attempt to stop gracefully, finish any currently active checks, and then output the results gathered up to that point (both to the console and to files if -o was specified). Pressing Ctrl+C a second time will force an immediate exit.

## Output

1. Console Output: The script prints categorized lists to the standard output:

* Working Subdomains: Lists subdomains that responded successfully (includes HTTP status code and protocol used).

* Not Working Subdomains: Lists subdomains that failed (includes status like Not Resolving, Timeout, Connection Error, etc., and the reason).

* Interrupted: Lists subdomains whose checks might have been cut short by user interruption (if applicable).

* Potentially Sensitive Subdomains: Lists all subdomains (regardless of working status) whose names matched keywords. Includes the detected keywords and the current status.

2. CSV Files (Optional): If the -o PREFIX option is used, the following files are created:

* PREFIX_working.csv: Columns: Subdomain, Status Reason

* PREFIX_not_working.csv: Columns: Subdomain, Status, Reason (Includes interrupted if any)

* PREFIX_potentially_sensitive.csv: Columns: Subdomain, Current Status, Keywords Found, Status Reason

## Configuration
Some parameters can be easily modified directly within the script file (e.g., subdomain_analyzer.py):

* SENSITIVE_KEYWORDS: The list of keywords used to flag potentially sensitive subdomains.
* REQUEST_TIMEOUT: Default timeout value (can be overridden by -t).
* MAX_WORKERS: Default number of workers (can be overridden by -w).
* HEADERS: The User-Agent string used for requests.

## ⚠️ Important Considerations & Disclaimer ⚠️
Authorization Required: DO NOT run this script against any target domains or subdomains without explicit, written permission from the owner of the systems. Unauthorized scanning is illegal and unethical in most jurisdictions. Running scans without permission can lead to legal action, IP blocking, and other serious consequences.

* VDP/Bug Bounty Programs: If using this script as part of an authorized Vulnerability Disclosure Program (VDP) or Bug Bounty program (e.g., via Bugcrowd, HackerOne):

* Strictly adhere to the Scope and Rules of Engagement (RoE) defined by the specific program.

* Verify that all target subdomains are explicitly listed as in-scope. Scanning out-of-scope assets is a violation.

* Check the rules regarding automated scanning and reconnaissance tools. Many programs restrict or prohibit automated scanning or require very low request rates.

* Significantly lower the concurrency using the -w flag (e.g., -w 1 or -w 2) to minimize disruption and avoid violating program rules or triggering defensive mechanisms (WAF/IPS). Consider if explicit rate-limiting (e.g., 
  adding delays) is necessary based on the RoE.

* "Potentially Sensitive" is a Heuristic: The keyword matching feature is a simple heuristic based on common naming conventions. It does not guarantee that a flagged subdomain actually contains sensitive data or 
  vulnerabilities. It serves only as an indicator for potential manual investigation during authorized assessments.

* Potential for Blocking: Automated scanning, even with low concurrency, can be detected by Web Application Firewalls (WAFs) or Intrusion Prevention Systems (IPS). This may lead to your IP address being blocked by the 
  target organization, even during authorized tests. Proceed with caution and respect the target's infrastructure.
