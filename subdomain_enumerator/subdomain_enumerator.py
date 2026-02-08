import sys                      # For command-line arguments
import requests                 # To send HTTP/HTTPS requests
from tqdm import tqdm           # For progress bar

# Read domains from file
domain_list = open("domain_list.txt").read()
cleaned_domain_list = domain_list.splitlines()

working = []    # Stores reachable domains
failed = []     # Stores unreachable domains

# Progress bar setup
pbar = tqdm(
    cleaned_domain_list,
    desc="Scanning",
    position=0,
    leave=True,
    bar_format="{l_bar}{bar} {percentage:3.0f}%",
    miniters=10,
    mininterval=1,
    file=sys.stdout,
    dynamic_ncols=False
)

# Loop through each subdomain
for dom in pbar:
    # Build full URLs using input domain
    http_url = f"http://{dom}.{sys.argv[1]}"
    https_url = f"https://{dom}.{sys.argv[1]}"

    try:
        # Send requests
        http_response = requests.get(http_url)
        https_response = requests.get(https_url)

        # Get status codes
        http_status_code = http_response.status_code
        https_status_code = https_response.status_code

        # If request succeeds, mark as working
        working.append(f"{dom}.{sys.argv[1]} --> 200")

    except requests.ConnectionError:
        # If connection fails, mark as failed
        failed.append(f"{dom}.{sys.argv[1]}")

# Save results to file
with open("Scan_output.txt", "w") as f:
    f.write("===== WORKING DOMAINS =====\n")
    for w in working:
        f.write(f"{w}\n")

    f.write("\n===== FAILED DOMAINS =====\n")
    for d in failed:
        f.write(f"{d}\n")

print("Scan Complete saved to Scan_output.txt")
