# XSS Finder

## Overview
XSS Finder is an automated tool designed to discover **Cross-Site Scripting (XSS) vulnerabilities** in web applications. It leverages **Subfinder**, **Httpx**, and **Katana** to identify live subdomains and extract URLs for testing with user-defined payloads.

## Features
- Automatically discovers subdomains using **Subfinder**
- Filters active subdomains using **Httpx**
- Extracts URLs from active subdomains using **Katana**
- Filters URLs with query parameters for XSS testing
- Tests each URL with multiple user-defined payloads
- Supports multithreading for faster execution

## Requirements
Ensure you have the following tools installed:
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Httpx](https://github.com/projectdiscovery/httpx)
- [Katana](https://github.com/projectdiscovery/katana)
- Python 3

Install Python dependencies:
```sh
pip install requests
```

## Usage
1. Run the script:
   ```sh
   python xss_finder.py
   ```
2. Enter the target domain when prompted.
3. Provide a file containing XSS payloads.
4. The tool will find subdomains, filter live ones, extract URLs, and test for XSS vulnerabilities.
5. Results will be saved in `xss_results.txt`.

## Output Files
- **subdomains.txt** - List of discovered subdomains
- **alive_subdomains.txt** - Filtered list of live subdomains
- **urls.txt** - Extracted URLs from live subdomains
- **filtered_urls.txt** - URLs with query parameters
- **xss_results.txt** - Vulnerable URLs detected

## Disclaimer
This tool is intended for ethical security testing **only**. Unauthorized use against websites without permission is illegal.

## Author
[XBUG01X]

