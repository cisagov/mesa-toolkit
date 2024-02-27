import sys
import json
from jinja2 import Template
import glob
import os
import subprocess
import shutil

# Definte the template file to be used
template_file = "templates/template.html"

# Inputs provided by the user
customer_name = input("Enter customer full name: ")
customer_initials = input("Enter customer initials: ")
project_name = input("Enter project name: ")
project_name = project_name.lower()

# Define the home and root directories
home = os.getcwd()
root_directory = "data/"

# Unzip scan file within data directory
os.chdir(root_directory)
os.mkdir(f"{project_name}-all_checks")
os.system(f"unzip {project_name}-all_checks.zip -d {project_name}-all_checks")
os.chdir(home)

# List of file extensions to remove
extensions_to_remove = [".failed", ".complete", ".intermediate-complete", ".started"]

# Function to remove files with specific extensions
def remove_files_with_extensions(dir_path, extensions):
    for dirpath, dirnames, filenames in os.walk(dir_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            for extension in extensions:
                if filename.endswith(extension):
                    print(f"Removing: {file_path}")
                    os.remove(file_path)

# Call the function to remove files with specified extensions
remove_files_with_extensions(root_directory, extensions_to_remove)

# Remove bloated cache files
os.system(f"rm -rf /root/.mesa/projects/data/{project_name}-all_checks/Vulnerability_Scans/.cache")
os.system(f"rm -rf /root/.mesa/projects/data/{project_name}-all_checks/Insecure_Default_Configuration/Default_Logins/.cache")

# Define locations for input files
scope_file = f"data/{project_name}-all_checks/scope.txt"
exclusions_file = f"data/{project_name}-all_checks/exclusions.txt"
discovery_file = f"data/{project_name}-all_checks/Port_Scans/DISCOVERY/Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt"
tcp_ports_file = f"data/{project_name}-all_checks/Port_Scans/FULL/Parsed-Results/Port-Lists/TCP-Ports-List.txt"
aquatone_urls_file = f"data/{project_name}-all_checks/Web_App_Enumeration/aquatone_urls.txt"

# Define a function to count lines in a file and remove leading whitespace
def count_lines(filename):
    with open(filename, 'r') as file:
        return len([line.strip() for line in file.readlines()])

# Execute nmap command and count scanned hosts
command = f"nmap -Pn -n -sL -iL {scope_file} --excludefile {exclusions_file} | cut -d ' ' -f 5 | grep -v 'nmap\\|address' | wc -l | sed 's/^[[:space:]]*//g'"
output = subprocess.check_output(command, shell=True, text=True)
scanned_hosts = int(output.strip())
os.system(f"nmap -Pn -n -sL -iL {scope_file} --excludefile {exclusions_file} | cut -d ' ' -f 5 | grep -v 'nmap\\|address' > data/{project_name}-all_checks/consolidated_scope.txt")

# Count live hosts
live_hosts = count_lines(discovery_file)

# Count unique ports
unique = count_lines(tcp_ports_file)

# Count web servers
web_servers = count_lines(aquatone_urls_file)

# Count cleartext hosts
cleartext_hosts = sum(count_lines(file) for file in glob.glob(f"data/{project_name}-all_checks/Encryption_Check/Cleartext_Protocols/*.txt"))

# Count default logins
default_logins = sum(count_lines(file) for file in glob.glob(f"data/{project_name}-all_checks/Insecure_Default_Configuration/Default_Logins/*affected_hosts.txt"))

# Count unique vulnerabilities
unique_vulns = len(set(line.split('-')[1] for file in glob.glob(f"data/{project_name}-all_checks/Vulnerability_Scans/*affected_hosts.txt") for line in open(file)))

# Count critical vulnerabilities
critical_vulns = sum(count_lines(file) for file in glob.glob(f"data/{project_name}-all_checks/Vulnerability_Scans/*_critical_affected_hosts.txt"))

# Count high vulnerabilities
high_vulns = sum(count_lines(file) for file in glob.glob(f"data/{project_name}-all_checks/Vulnerability_Scans/*_high_affected_hosts.txt"))

# Count medium vulnerabilities
medium_vulns = sum(count_lines(file) for file in glob.glob(f"data/{project_name}-all_checks/Vulnerability_Scans/*_medium_affected_hosts.txt"))

# Count low vulnerabilities
low_vulns = sum(count_lines(file) for file in glob.glob(f"data/{project_name}-all_checks/Vulnerability_Scans/*_low_affected_hosts.txt"))

# Count informational vulnerabilities
info_vulns = sum(count_lines(file) for file in glob.glob(f"data/{project_name}-all_checks/Vulnerability_Scans/*_informational_affected_hosts.txt"))

# Count SMB Signing Disabled
smb_sign_disable = sum(count_lines(file) for file in glob.glob(f"data/{project_name}-all_checks/Insecure_Default_Configuration/SMB_Signing/*_SMB_Signing_Disabled.txt"))

# Create a dictionary to store the variables
variables = {
    "project_name": project_name,
    "customer_name": customer_name,
    "customer_initials": customer_initials,
    "ip_addr_scanned": scanned_hosts,
    "live_hosts": live_hosts,
    "unique_ports": unique,
    "web_servers": web_servers,
    "cleartext_hosts": cleartext_hosts,
    "default_logins": default_logins,
    "unique_vulns": unique_vulns,
    "critical_vulns": critical_vulns,
    "high_vulns": high_vulns,
    "medium_vulns": medium_vulns,
    "low_vulns": low_vulns,
    "info_vulns": info_vulns,
    "smb_sign_disabled": smb_sign_disable
}

# Write the variables to a JSON file
with open('variables.json', 'w') as json_file:
    json.dump(variables, json_file, indent=4)

# Read the template file
try:
    with open(template_file, 'r') as template_file:
        template_content = template_file.read()
except FileNotFoundError:
    print(f"Error: Template file '{template_file}' not found.")
    sys.exit(1)

try:
    with open('variables.json', 'r') as json_file:
        data = json.load(json_file)
except FileNotFoundError:
    print("Error: Data file 'variables.json' not found.")
    sys.exit(1)

# Render the template with the data
template = Template(template_content)
rendered_html = template.render(data)

# Write the rendered HTML to the output file
os.system(f'mkdir -p output/{project_name}/data output/{project_name}/report output/{project_name}/customer_deliverable')
output_file = f"output/{project_name}/report/{customer_name}-Report.html"
with open(output_file, 'w') as output_file:
    output_file.write(rendered_html)

# Create deliverable zip file to provide to the customer
os.system(f'cp -r data/{project_name}-all_checks output/{project_name}/data')
os.system(f'cp -r templates/digest_images output/{project_name}/data')
os.system(f'zip -rv {customer_initials}-Customer-Report.zip output/{project_name}/data "output/{project_name}/report/{customer_name}-Report.html"')
os.system(f'mv {customer_initials}-Customer-Report.zip output/{project_name}/customer_deliverable')

# Remove variables.json after report generation
os.remove("variables.json")

# Print statement providing user with location of deliverable
print(f'{customer_initials}-Report.zip can be found within the output/{project_name}/customer_deliverable directory.')