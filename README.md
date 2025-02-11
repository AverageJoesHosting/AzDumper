# **AzDumper - Azure Security Audit & Misconfiguration Detection Tool**  
**Author:** KizzMyAnthia  
**Version:** 1.0  

## **📌 Overview**
AzDumper is a **powerful security assessment tool** for **Azure environments**. It collects **security-related configurations** and **detects misconfigurations** to help penetration testers, security engineers, and cloud administrators **identify vulnerabilities** in their Azure subscriptions.  

## **🚀 Features**
✅ **Collects security-related Azure data** (IAM, NSGs, Firewall, SQL, Key Vaults, Storage, etc.)  
✅ **Detects misconfigurations** (e.g., public storage, open firewall rules, overly privileged IAM roles)  
✅ **Supports both Windows & Linux**  
✅ **Fast execution using parallelized requests**  
✅ **Handles transient errors with automatic retries**  
✅ **Generates structured JSON reports & security findings**  

## **📂 Data Collected**
AzDumper gathers **detailed Azure resource configurations**, including:  
- **Subscriptions & Users:** Tenant info, IAM roles, assigned permissions  
- **Networking:** NSGs, public IPs, firewall rules  
- **Storage & Key Vaults:** Public storage, unsecured Key Vaults  
- **Compute & Databases:** Azure Kubernetes (AKS), SQL Servers, SQL Databases  
- **Security & Monitoring:** Azure Security Center, Log Analytics, compliance policies  

## **⚙️ Installation**
### **🔹 Prerequisites**
Before running AzDumper, ensure you have:  
✔️ **Python 3.7+** installed  
✔️ **Azure CLI** installed & configured (`az login`)  
✔️ **Required Azure permissions** (Read-only access or higher)  

### **🔹 Install Azure CLI (if not installed)**
#### **Linux/macOS**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```
#### **Windows (PowerShell)**
```powershell
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
Start-Process msiexec.exe -ArgumentList "/I AzureCLI.msi /quiet" -NoNewWindow -Wait
```

## **🔧 Usage**
### **🔹 Run AzDumper**
```bash
python AzDumper.py --output my_audit_results
```
By default, reports are saved in `azure_audit_output/`. Use `--output <folder>` to specify a different directory.

### **🔹 Example Output Structure**
```
my_audit_results/
│── subscriptions.json
│── users.json
│── role_assignments.json
│── nsgs.json
│── public_ips.json
│── storage_accounts.json
│── security_recommendations.json
│── log_analytics_workspaces.json
│── firewall_rules.json
│── key_vaults.json
│── sql_servers.json
│── sql_databases.json
│── aks_clusters.json
│── security_findings.txt  <-- Misconfiguration Report
```

## **🛠️ Options**
| **Option**   | **Description**                                       | **Example** |
|-------------|------------------------------------------------|----------------|
| `--output`   | Specify output folder for reports | `--output my_results` |

## **🔍 Security Checks Performed**
AzDumper automatically detects **critical misconfigurations**, including:

### **🔹 IAM Security Risks**
✅ High-privilege users (`Owner`, `Contributor`)  
✅ Excessive permissions on service principals  

### **🔹 Network Security**
✅ **Publicly accessible NSGs** (Allowing `0.0.0.0/0`)  
✅ **Exposed public IPs**  

### **🔹 Storage & Key Vaults**
✅ **Publicly accessible storage accounts**  
✅ **Key Vaults missing soft delete protection**  

### **🔹 Database Security**
✅ **SQL servers exposed to the internet**  
✅ **Databases without proper security configurations**  

### **🔹 Security Compliance**
✅ **Security Center recommendations not implemented**  
✅ **Missing Log Analytics & Monitoring configurations**  

## **📜 Example Output (Security Findings)**
```
⚠️ High privilege user: admin@example.com (Owner)
⚠️ NSG 'nsg-public' allows unrestricted access on port 3389 (RDP)
⚠️ Public IP detected: 52.176.12.34 assigned to 'vm-webserver'
⚠️ Storage account 'companyfiles' has public access enabled
⚠️ Key Vault 'kv-secrets' does not have soft delete enabled
⚠️ SQL Server 'sql-prod' is publicly accessible: sql-prod.database.windows.net
⚠️ No Log Analytics workspace found. Monitoring may not be enabled
```

## **🖥️ Supported Platforms**
✅ **Windows**  
✅ **Linux**  
✅ **macOS**  

## **🛠️ Troubleshooting**
### **🔹 Azure CLI Not Installed?**
Check installation:
```bash
az --version
```
If not found, install Azure CLI from [Microsoft Docs](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli).

### **🔹 Azure CLI Login Required**
Ensure you're authenticated:
```bash
az login
```
For service principal authentication:
```bash
az login --service-principal -u <APP_ID> -p <PASSWORD> --tenant <TENANT_ID>
```

### **🔹 Insufficient Permissions?**
Ensure your user has at least **Reader Role** across your Azure resources.

## **📜 License**
AzDumper is an **open-source security auditing tool**. Use responsibly and only on **your own** Azure environments or with **explicit authorization**.

## **👨‍💻 Author**
**KizzMyAnthia**  

