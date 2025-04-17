import requests
import urllib3
from requests.auth import HTTPBasicAuth
import csv

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === F5 Device Details ===
f5_host = "https://10.1.1.11"  # Replace with your F5 host
username = "admin"  # Replace with your F5 username
password = "kailas@123"  # Replace with your F5 password
output_csv_file = "f5_asm_policy_vips.csv"  # Name of the CSV file to create

auth = HTTPBasicAuth(username, password)

def fetch_json(url):
    """Fetches JSON data from a given URL with basic authentication and SSL verification disabled."""
    try:
        resp = requests.get(url, auth=auth, verify=False)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return None

# === Step 1: Fetch all ASM policies ===
print("📡 Fetching all ASM policies...")
policies_url = f"{f5_host}/mgmt/tm/asm/policies?$select=name,id,enforcementMode"
all_policies_data = fetch_json(policies_url)
all_policies = all_policies_data.get("items", []) if all_policies_data else []

if not all_policies:
    print("❌ No ASM policies found.")
    exit()

# === Step 2: Prepare CSV file ===
with open(output_csv_file, 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)

    # Write header row
    csv_writer.writerow(["Policy Name", "Enforcement Mode", "Direct VIPs", "Manual VIPs"])

    # === Step 3: Iterate through each policy and fetch detailed virtual server info ===
    print("\n📝 Writing data to CSV file: {}".format(output_csv_file))
    for policy in all_policies:
        policy_name = policy.get("name", "N/A")
        policy_id = policy.get("id")
        enforcement_mode = policy.get("enforcementMode", "N/A")
        direct_vips = "None"
        manual_vips = "None"

        if policy_id:
            detailed_policy_url = f"{f5_host}/mgmt/tm/asm/policies/{policy_id}?$select=virtualServers,manualVirtualServers"
            detailed_policy_data = fetch_json(detailed_policy_url)

            if detailed_policy_data:
                direct_vips_list = detailed_policy_data.get("virtualServers", [])
                manual_vips_list = detailed_policy_data.get("manualVirtualServers", [])
                direct_vips = ", ".join(direct_vips_list) if direct_vips_list else "None"
                manual_vips = ", ".join(manual_vips_list) if manual_vips_list else "None"
            else:
                print(f"⚠️ Could not fetch details for policy: {policy_name} (ID: {policy_id})")

        # Write data row to CSV
        csv_writer.writerow([policy_name, enforcement_mode, direct_vips, manual_vips])

print("\n✅ Data successfully written to {}".format(output_csv_file))
