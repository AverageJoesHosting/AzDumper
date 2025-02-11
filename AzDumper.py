"""
AzDumper - Azure Security Audit & Misconfiguration Detection Tool
Author: KizzMyAnthia
Version: 1.0
"""

import json
import os
import argparse
import subprocess
import concurrent.futures
import time
from datetime import datetime

# Global Constants
MAX_RETRIES = 3  # Number of retries for Azure CLI commands
OUTPUT_FOLDER = "azure_audit_output"

# Function to execute Azure CLI commands safely
def run_az_command(command):
    """Runs Azure CLI command with error handling and retries."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                print(f"⚠️ Error running command: {command} (Attempt {attempt}/{MAX_RETRIES})")
                print(f"Azure CLI Error: {result.stderr.strip()}")
        except Exception as e:
            print(f"❌ Exception running command: {command} -> {e}")

        time.sleep(2)  # Delay between retries

    print(f"❌ Failed to execute command: {command} after {MAX_RETRIES} attempts.")
    return None

# Function to save collected data
def save_data(output_folder, filename, data):
    """Save collected Azure data to JSON files in a structured format."""
    os.makedirs(output_folder, exist_ok=True)
    file_path = os.path.join(output_folder, filename)
    
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"✅ Data saved: {file_path}")
    except Exception as e:
        print(f"❌ Error saving {filename}: {e}")

# Function to collect security data in parallel
def collect_azure_security(output_folder):
    """Collect Azure security data concurrently."""
    print("\n🔍 Collecting Azure security data...")

    commands = {
        "subscriptions": "az account list --output json",
        "users": "az ad user list --output json",
        "role_assignments": "az role assignment list --all --output json",
        "nsgs": "az network nsg list --output json",
        "public_ips": "az network public-ip list --output json",
        "storage_accounts": "az storage account list --output json",
        "security_recommendations": "az security assessment list --output json",
        "log_analytics_workspaces": "az monitor log-analytics workspace list --output json",
        "firewall_rules": "az network firewall list --output json",
        "key_vaults": "az keyvault list --output json",
        "sql_servers": "az sql server list --output json",
        "sql_databases": "az sql db list --output json",
        "aks_clusters": "az aks list --output json",
    }

    security_data = {}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_command = {executor.submit(run_az_command, cmd): key for key, cmd in commands.items()}
        for future in concurrent.futures.as_completed(future_to_command):
            key = future_to_command[future]
            try:
                result = future.result() or []
                security_data[key] = result
                save_data(output_folder, f"{key}.json", result)
            except Exception as e:
                print(f"❌ Error retrieving {key}: {e}")

    return security_data

# Function to check for IAM misconfigurations
def check_iam_issues(users, role_assignments):
    findings = []
    high_privilege_roles = ["Owner", "Contributor"]

    for role in role_assignments:
        if role.get("roleDefinitionName") in high_privilege_roles:
            findings.append(f"⚠️ High privilege user: {role['principalName']} ({role['roleDefinitionName']})")

    return findings

# Function to check for NSG misconfigurations
def check_nsg_issues(nsgs):
    findings = []

    for nsg in nsgs:
        for rule in nsg.get("securityRules", []):
            if rule.get("access") == "Allow" and rule.get("sourceAddressPrefix", "") == "0.0.0.0/0":
                findings.append(f"⚠️ NSG '{nsg['name']}' allows unrestricted access on port {rule['destinationPortRange']}")

    return findings

# Function to check public exposure risks
def check_public_exposure(public_ips, storage_accounts, key_vaults, sql_servers):
    findings = []

    for ip in public_ips:
        if ip.get("ipAddress"):
            findings.append(f"⚠️ Public IP: {ip['ipAddress']} assigned to {ip['name']}")

    for storage in storage_accounts:
        if storage.get("allowBlobPublicAccess", False):
            findings.append(f"⚠️ Storage account '{storage['name']}' has public access enabled")

    for vault in key_vaults:
        if vault.get("properties", {}).get("enableSoftDelete", False) is False:
            findings.append(f"⚠️ Key Vault '{vault['name']}' does not have soft delete enabled")

    for sql in sql_servers:
        if sql.get("fullyQualifiedDomainName"):
            findings.append(f"⚠️ SQL Server '{sql['name']}' is publicly accessible: {sql['fullyQualifiedDomainName']}")

    return findings

# Function to check for security compliance issues
def check_security_compliance(security_recommendations):
    findings = []

    for rec in security_recommendations:
        if rec.get("status", "").lower() == "unhealthy":
            findings.append(f"⚠️ Security Issue: {rec['displayName']} is not compliant")

    return findings

# Function to check monitoring issues
def check_monitoring_issues(log_analytics_workspaces):
    return ["⚠️ No Log Analytics workspace found. Monitoring may not be enabled"] if not log_analytics_workspaces else []

# Function to perform security checks
def run_security_checks(output_folder):
    print("\n🔍 Running Security Misconfiguration Checks...")
    security_findings = []

    try:
        users = json.load(open(os.path.join(output_folder, "users.json")))
        role_assignments = json.load(open(os.path.join(output_folder, "role_assignments.json")))
        nsgs = json.load(open(os.path.join(output_folder, "nsgs.json")))
        public_ips = json.load(open(os.path.join(output_folder, "public_ips.json")))
        storage_accounts = json.load(open(os.path.join(output_folder, "storage_accounts.json")))
        security_recommendations = json.load(open(os.path.join(output_folder, "security_recommendations.json")))
        log_analytics_workspaces = json.load(open(os.path.join(output_folder, "log_analytics_workspaces.json")))
        key_vaults = json.load(open(os.path.join(output_folder, "key_vaults.json")))
        sql_servers = json.load(open(os.path.join(output_folder, "sql_servers.json")))

        security_findings.extend(check_iam_issues(users, role_assignments))
        security_findings.extend(check_nsg_issues(nsgs))
        security_findings.extend(check_public_exposure(public_ips, storage_accounts, key_vaults, sql_servers))
        security_findings.extend(check_security_compliance(security_recommendations))
        security_findings.extend(check_monitoring_issues(log_analytics_workspaces))

        with open(os.path.join(output_folder, "security_findings.txt"), "w") as f:
            f.write("\n".join(security_findings))

        print("\n🔴 Security Findings:")
        for finding in security_findings:
            print(finding)

        print(f"\n✅ Misconfiguration report saved in '{output_folder}/security_findings.txt'")

    except FileNotFoundError:
        print("⚠️ Error: Security data not found. Run 'Collect Security Data' first.")

# Main Execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AzDumper - Azure Security Audit Tool")
    parser.add_argument("--output", type=str, default=OUTPUT_FOLDER, help="Output folder for collected data")
    args = parser.parse_args()

    collect_azure_security(args.output)
    run_security_checks(args.output)
