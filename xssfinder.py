import requests
import subprocess
import threading
from queue import Queue

# Configuration
WAYBACK_FILE = "urls.txt"
FILTERED_FILE = "filtered_urls.txt"
RESULTS_FILE = "xss_results.txt"
SUBDOMAINS_FILE = "subdomains.txt"
ALIVE_SUBDOMAINS_FILE = "alive_subdomains.txt"

# Thread-safe queue for processing
queue = Queue()

# Banner
def banner():
    print("=" * 50)
    print("      Automated XSS Vulnerability Finder      ")
    print("=" * 50)

# Fetch subdomains using Subfinder
def fetch_subdomains(domain):
    print("[+] Finding subdomains for:", domain)
    try:
        with open(SUBDOMAINS_FILE, "w") as outfile:
            subprocess.run(["subfinder", "-d", domain], stdout=outfile, check=True)
        print(f"[+] Subdomains saved to {SUBDOMAINS_FILE}")
    except FileNotFoundError:
        print("[-] 'subfinder' is not installed. Install it using:")
        print("    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        exit(1)

# Filter alive subdomains using Httpx
def filter_alive_subdomains():
    print("[+] Checking alive subdomains...")
    try:
        with open(ALIVE_SUBDOMAINS_FILE, "w") as outfile:
            subprocess.run(["httpx", "-l", SUBDOMAINS_FILE, "-silent"], stdout=outfile, check=True)
        print(f"[+] Alive subdomains saved to {ALIVE_SUBDOMAINS_FILE}")
    except FileNotFoundError:
        print("[-] 'httpx' is not installed. Install it using:")
        print("    go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        exit(1)

# Fetch URLs using Katana
def fetch_urls():
    print("[+] Fetching URLs from alive subdomains...")
    try:
        with open(WAYBACK_FILE, "w") as outfile:
            subprocess.run(["katana", "-list", ALIVE_SUBDOMAINS_FILE, "-silent"], stdout=outfile, check=True)
        print(f"[+] URLs saved to {WAYBACK_FILE}")
    except FileNotFoundError:
        print("[-] 'katana' is not installed. Install it using:")
        print("    go install github.com/projectdiscovery/katana/cmd/katana@latest")
        exit(1)

# Filter URLs with query parameters
def filter_urls():
    print("[+] Filtering URLs with query parameters...")
    with open(WAYBACK_FILE, "r") as infile, open(FILTERED_FILE, "w") as outfile:
        for line in infile:
            if "=" in line:
                outfile.write(line)
    print(f"[+] Filtered URLs saved to {FILTERED_FILE}")

# Load payloads from file
def load_payloads(file_path):
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print("[-] Payload file not found!")
        exit(1)

# Test a single URL for XSS with multiple payloads
def test_url(payloads):
    while not queue.empty():
        url = queue.get()
        for payload in payloads:
            test_url = url.strip().replace("=", f"={payload}")
            try:
                response = requests.get(test_url, timeout=10)
                if payload in response.text:
                    print(f"[+] XSS Vulnerability Found: {test_url}")
                    with open(RESULTS_FILE, "a") as results:
                        results.write(f"Vulnerable: {test_url}\n")
                else:
                    print(f"[-] No XSS Vulnerability: {test_url}")
            except requests.RequestException as e:
                print(f"[-] Error testing URL {test_url}: {e}")
        queue.task_done()

# Main function
def main():
    banner()
    
    # Input target domain
    domain = input("Enter the target domain (e.g., example.com): ").strip()
    if not domain:
        print("[-] Target domain is required!")
        exit(1)
    
    # Input payload file
    payload_file = input("Enter the payload file path: ").strip()
    if not payload_file:
        print("[-] Payload file is required!")
        exit(1)
    
    # Load payloads
    payloads = load_payloads(payload_file)
    print(f"[+] Loaded {len(payloads)} payloads from {payload_file}")
    
    # Step 1: Fetch subdomains
    fetch_subdomains(domain)
    
    # Step 2: Filter alive subdomains
    filter_alive_subdomains()
    
    # Step 3: Fetch URLs using Katana
    fetch_urls()
    
    # Step 4: Filter URLs
    filter_urls()
    
    # Step 5: Load URLs into queue for testing
    with open(FILTERED_FILE, "r") as infile:
        for line in infile:
            queue.put(line)
    
    print("[+] Starting XSS testing...")
    
    # Step 6: Multithreaded XSS testing
    threads = []
    for _ in range(10):  # Number of threads
        t = threading.Thread(target=test_url, args=(payloads,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()  # Wait for all threads to finish
    
    print("[+] XSS testing completed. Results saved to:", RESULTS_FILE)

if __name__ == "__main__":
    main()
