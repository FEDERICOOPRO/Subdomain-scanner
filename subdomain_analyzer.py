#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import requests
import socket
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import sys
import signal # To handle Ctrl+C
import time   # For potential waits
from urllib3.exceptions import InsecureRequestWarning

# --- Configuration ---
# Keywords that might indicate sensitive or interesting subdomains
SENSITIVE_KEYWORDS = [
    'admin', 'adm', 'backup', 'bak', 'config', 'cfg',
    'db', 'sql', 'mysql', 'mongo', 'redis',
    'dev', 'devel', 'development', 'test', 'tst', 'staging', 'stg',
    'internal', 'int', 'private', 'vpn', 'corp',
    'api', 'rest', 'soap',
    'git', 'svn', 'repo',
    'jira', 'confluence', 'jenkins', 'ci', 'cd',
    'login', 'signin', 'auth', 'sso',
    'portal', 'dashboard', 'control', 'panel',
    'mail', 'webmail', 'owa',
    'ftp', 'sftp', 'ssh',
    'legacy', 'old',
    'debug', 'trace',
    'secret', 'password', 'pwd',
    'payment', 'billing', 'finance'
]

# Timeout for HTTP/HTTPS requests (in seconds)
REQUEST_TIMEOUT = 10

# Maximum number of threads to use for parallel requests
MAX_WORKERS = 10

# User-Agent to use for requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Ignore invalid SSL certificate warnings (use with caution)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Global variable to signal interruption ---
shutdown_requested = False

# --- Handler function for the interruption signal ---
def handle_shutdown(sig, frame):
    """Sets the shutdown flag when SIGINT (Ctrl+C) is received."""
    global shutdown_requested
    if not shutdown_requested:
        # Use print to ensure it's displayed even if logging is set to higher levels
        print("\n\n*** Interruption requested (Ctrl+C)! ***")
        print("Stopping submission of new requests and waiting for active tasks...")
        print("Press Ctrl+C again to force exit (you might lose the last output).")
        logging.warning("Interruption requested. Attempting graceful shutdown.")
        shutdown_requested = True
    else:
        print("\nForcing immediate exit!")
        logging.warning("Second interruption requested. Forcing exit.")
        sys.exit(1) # Exit immediately

# --- Subdomain check function ---
def check_subdomain(subdomain):
    """
    Checks the status of a single subdomain and if it contains sensitive keywords.
    Returns a tuple: (subdomain, status, is_potentially_sensitive, reason)
    """
    subdomain = subdomain.strip().lower()
    if not subdomain:
        return (None, 'Invalid', False, 'Empty subdomain entry')

    # Check for sensitive keywords in the name (first part of the domain)
    try:
        first_part = subdomain.split('.')[0]
        is_potentially_sensitive = any(re.search(rf'\b{keyword}\b', first_part, re.IGNORECASE) for keyword in SENSITIVE_KEYWORDS)
    except IndexError: # Handles the case of a string without dots
        is_potentially_sensitive = False

    # 1. DNS resolution attempt
    try:
        socket.gethostbyname(subdomain)
    except socket.gaierror:
        logging.debug(f"DNS resolution failed for {subdomain}")
        return (subdomain, 'Not Resolving', is_potentially_sensitive, 'DNS lookup failed')
    except Exception as e:
         logging.warning(f"Unexpected DNS error for {subdomain}: {e}")
         # Do not return, try HTTP/S requests anyway

    # 2. HTTP/HTTPS connection attempt
    protocols = ['https', 'http']
    success = False
    status_reason = "No response after DNS resolution" # Default reason if both fail

    for proto in protocols:
        # If interruption was requested WHILE we were in this loop, exit early
        if shutdown_requested:
             logging.debug(f"Shutdown requested during check for {subdomain}, skipping further checks.")
             status_reason = "Scan interrupted by user"
             break # Exit the protocol loop (http/https)

        url = f"{proto}://{subdomain}"
        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                verify=False, # Ignore SSL errors (important for dev/test/internal)
                allow_redirects=True # Follow redirects
            )
            success = True
            status_code = response.status_code
            status_reason = f"Responded ({proto.upper()}) - Status: {status_code}"
            logging.debug(f"Success connecting to {url} - Status: {status_code}")
            break # Success, exit the protocol loop

        except requests.exceptions.Timeout:
            status_reason = f"Timeout ({proto.upper()})"
            logging.debug(f"Timeout connecting to {url}")
            continue # Try the other protocol if available
        except requests.exceptions.SSLError as e:
             # Don't log the entire SSL exception unless debugging, can be verbose
             status_reason = f"SSL Error ({proto.upper()})"
             logging.debug(f"SSL Error connecting to {url}: {e}")
             continue # Try HTTP if HTTPS fails due to SSL
        except requests.exceptions.ConnectionError:
            status_reason = f"Connection Error ({proto.upper()})"
            logging.debug(f"Connection error for {url}")
            continue # Try the other protocol if available
        except requests.exceptions.RequestException as e:
            status_reason = f"Request Error ({proto.upper()}): {type(e).__name__}"
            logging.warning(f"Error checking {url}: {e}")
            break # Generic error, don't try the other protocol

    # Determine the final status based on success or failure
    if success:
        final_status = 'Working'
    elif 'DNS lookup failed' in status_reason: # If DNS failed initially
         final_status = 'Not Resolving'
    elif shutdown_requested and 'Scan interrupted' in status_reason:
        final_status = 'Interrupted'
    elif 'Timeout' in status_reason:
         final_status = 'Timeout' # If the last recorded error was a timeout
    else: # Otherwise, likely a generic connection error
         final_status = 'Connection Error'

    return (subdomain, final_status, is_potentially_sensitive, status_reason)


# --- Main Function ---
def main(csv_filepath, output_prefix):
    """
    Reads the CSV, starts the checks, handles interruption, and produces output.
    """
    # --- Register the handler for SIGINT at the beginning of main ---
    signal.signal(signal.SIGINT, handle_shutdown)

    subdomains = []
    logging.info(f"Reading subdomains from: {csv_filepath}")
    try:
        # Handles the specific format: subdomain,ip,boolean
        # We don't use csv.reader here because we only want the part before the first comma
        with open(csv_filepath, 'r', encoding='utf-8', errors='ignore') as csvfile:
            line_count = 0
            for line in csvfile:
                line_count += 1
                if shutdown_requested:
                    logging.warning("Interruption requested during CSV reading.")
                    break # Stop reading the file

                line = line.strip()
                if not line:
                    continue # Skip empty lines

                # Take only the part before the first comma
                parts = line.split(',', 1)
                subdomain = parts[0].strip()

                if subdomain:
                     # Very simple validation
                     if '.' in subdomain and not subdomain.startswith('.') and not subdomain.endswith('.'):
                        subdomains.append(subdomain)
                     else:
                        logging.warning(f"Skipping invalid entry on line {line_count}: '{subdomain}' (extracted from '{line}')")
                else:
                     logging.warning(f"Skipping empty subdomain entry on line {line_count} from line '{line}'")

    except FileNotFoundError:
        logging.error(f"Error: CSV file not found at '{csv_filepath}'")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading CSV file '{csv_filepath}': {e}")
        sys.exit(1)

    if not subdomains:
        logging.warning("No valid subdomains found in the CSV file.")
        return

    initial_count = len(subdomains)
    logging.info(f"Found {initial_count} valid subdomains to analyze.")
    logging.info(f"Starting analysis with {MAX_WORKERS} concurrent workers. Request timeout: {REQUEST_TIMEOUT}s.")
    logging.info("Press Ctrl+C to stop the analysis and get partial results.")

    results = {
        'working': [],
        'not_working': [],
        'potentially_sensitive': [],
        'interrupted': [] # List for explicitly interrupted tasks
    }
    futures = set() # Keep track of submitted futures
    processed_count = 0

    try:
        # Use ThreadPoolExecutor to run checks in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit initial tasks
            for subdomain in subdomains:
                if shutdown_requested:
                    logging.info("Interruption requested, no more tasks will be submitted.")
                    break # Stop submitting new tasks
                future = executor.submit(check_subdomain, subdomain)
                futures.add(future)

            submitted_count = len(futures)
            logging.info(f"Tasks submitted: {submitted_count}. Waiting for results...")

            # Process results as they complete
            for future in as_completed(futures):
                # Check if interruption was requested BEFORE getting the result
                # This avoids getting stuck on future.result() if the underlying task
                # is respecting the shutdown_requested flag.
                if shutdown_requested and not future.done():
                    # future.cancel() returns True if cancellation succeeds
                    # (i.e., the task hadn't already started running or finished)
                    if future.cancel():
                         logging.debug("Cancelled a future task that had not started yet.")
                         # We might want to track these separately, but not doing so for now
                    continue # Move to the next future in the as_completed set

                try:
                    # Get the result (might block briefly if the task is almost finished)
                    subdomain_res, status, is_sensitive, reason = future.result()
                    processed_count += 1

                    # Print progress occasionally
                    if processed_count % 50 == 0 or processed_count == submitted_count:
                         logging.info(f"Processed {processed_count}/{submitted_count} submitted tasks...")

                    if subdomain_res is None: # Invalid entry handled in check_subdomain
                        continue

                    result_entry = {'subdomain': subdomain_res, 'status': status, 'reason': reason}

                    # Classify the result
                    if status == 'Working':
                        results['working'].append(result_entry)
                    elif status == 'Interrupted':
                         results['interrupted'].append(result_entry)
                    else: # Not Resolving, Timeout, Connection Error, etc.
                        results['not_working'].append(result_entry)

                    # Flag as potentially sensitive regardless of status
                    if is_sensitive:
                        keywords_found = [kw for kw in SENSITIVE_KEYWORDS if re.search(rf'\b{kw}\b', subdomain_res.split('.')[0], re.IGNORECASE)]
                        results['potentially_sensitive'].append({
                            'subdomain': subdomain_res,
                            'status': status,
                            'reason': reason,
                            'keywords_found': keywords_found
                        })

                except Exception as exc:
                    processed_count += 1 # Also count errors as processed
                    logging.error(f"Error processing the result of a task: {exc}")
                    # We could try to retrieve the subdomain from the future if we had a map
                    # But for now, add it as a generic error
                    results['not_working'].append({'subdomain': 'Unknown (error during result processing)', 'status': 'Execution Error', 'reason': str(exc)})

                # If interruption was requested AFTER processing this result, exit now
                if shutdown_requested:
                    logging.info("Interruption detected after processing result, exiting loop.")
                    break

            # End of the as_completed loop

        # End of the 'with executor' block. Shutdown waits (by default) for running tasks.
        logging.info("ThreadPoolExecutor has completed shutdown.")
        if shutdown_requested:
             logging.warning(f"Analysis interrupted. Partial results for {processed_count} processed subdomains.")
        else:
             logging.info(f"Analysis completed for all {processed_count} submitted subdomains.")


    except KeyboardInterrupt:
        # Reached if Ctrl+C pressed outside the handler or a second time
        logging.warning("KeyboardInterrupt received (likely double press). Proceeding with partial output.")
        if not shutdown_requested: # If for some reason the handler didn't run
             handle_shutdown(signal.SIGINT, None) # Call it manually

    # --- Output Section ---
    # This is always executed, both after completion and after interruption
    print("\n--- Analysis Results " + ("(Partial)" if shutdown_requested else "(Complete)") + " ---")
    print(f"Subdomains processed: {processed_count} / {initial_count} (read from CSV)")

    print(f"\n[*] Working Subdomains ({len(results['working'])}):")
    for item in results['working']:
        print(f"  - {item['subdomain']} ({item['reason']})")

    print(f"\n[*] Not Working Subdomains ({len(results['not_working'])}):")
    # Sort by status to group similar errors
    results['not_working'].sort(key=lambda x: x.get('status', ''))
    for item in results['not_working']:
        print(f"  - {item['subdomain']} ({item.get('status','N/A')} - {item.get('reason','N/A')})")

    if results['interrupted']:
        print(f"\n[*] Interrupted by User ({len(results['interrupted'])}):")
        for item in results['interrupted']:
            print(f"  - {item['subdomain']} (Scan interrupted)")

    print(f"\n[*] Potentially Sensitive Subdomains ({len(results['potentially_sensitive'])}):")
    if results['potentially_sensitive']:
        print("  (Based on keywords in name - requires manual verification!)")
        results['potentially_sensitive'].sort(key=lambda x: x['subdomain'])
        for item in results['potentially_sensitive']:
             kw_str = ', '.join(item.get('keywords_found', []))
             print(f"  - {item['subdomain']} (Status: {item.get('status','N/A')}, Keywords: [{kw_str}])")
    else:
        print("  No subdomains flagged as potentially sensitive.")

    # --- Save results to file (optional) ---
    if output_prefix:
        logging.info(f"Saving {'partial ' if shutdown_requested else ''}results to files with prefix '{output_prefix}_'")
        try:
            # Save Working
            with open(f"{output_prefix}_working.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'Status Reason'])
                for item in results['working']:
                    writer.writerow([item['subdomain'], item['reason']])

            # Save Not Working (include Interrupted if desired)
            all_not_working = results['not_working'] + results['interrupted']
            all_not_working.sort(key=lambda x: x.get('status', ''))
            with open(f"{output_prefix}_not_working.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'Status', 'Reason'])
                for item in all_not_working:
                    writer.writerow([item.get('subdomain','N/A'), item.get('status','N/A'), item.get('reason','N/A')])

            # Save Potentially Sensitive
            with open(f"{output_prefix}_potentially_sensitive.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'Current Status', 'Keywords Found', 'Status Reason'])
                for item in results['potentially_sensitive']:
                    writer.writerow([item.get('subdomain','N/A'), item.get('status','N/A'), ', '.join(item.get('keywords_found',[])), item.get('reason','N/A')])

            logging.info(f"Results saved to {output_prefix}_*.csv files")

        except Exception as e:
            logging.error(f"Error saving results to files: {e}")

# --- Main execution block ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyzes subdomains from a CSV file (format: subdomain,ip,bool). Checks reachability and looks for sensitive keywords in the name. Press Ctrl+C to stop early and get partial results.",
        epilog="Example: python script.py subdomains.csv -o scan_results -w 20"
        )
    parser.add_argument("csv_file", help="Path to the CSV file containing subdomains (one per line, takes the value before the first comma).")
    parser.add_argument("-o", "--output", help="Prefix for output CSV files (e.g., 'scan_results'). If omitted, results are only printed to the screen.", default=None)
    parser.add_argument("-w", "--workers", type=int, help=f"Number of concurrent workers (default: {MAX_WORKERS}).", default=MAX_WORKERS)
    parser.add_argument("-t", "--timeout", type=int, help=f"Request timeout in seconds for HTTP/S checks (default: {REQUEST_TIMEOUT}).", default=REQUEST_TIMEOUT)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG level logging output.")

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Update global constants from command line
    REQUEST_TIMEOUT = args.timeout
    MAX_WORKERS = args.workers

    # Call the main function
    main(args.csv_file, args.output)

    logging.info("Script finished.")

# This file is part of HexFud Project
# Copyright (c) 2025 HexFud
# Released under the MIT License

