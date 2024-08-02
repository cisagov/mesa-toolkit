#!/usr/bin/python3
#Created by Miguel Rios and Adam Brown
import argparse
import shutil
import sys
import os
from datetime import datetime
import getpass
import subprocess
from mesa_toolkit.logger import logger
import json
from jinja2 import Template
import glob

STARTED_FILE = '.started'
RUNNING_FILE = '.running'
FAILED_FILE = '.failed'
COMPLETE_FILE = '.complete'

STATUS_CODE_COMPLETE_NOT_RAN = '-999'

MASSCAN_FOLDERS = '_Scans/Port_Scans/MASSCAN/'
NMAP_FOLDERS_DISC = '_Scans/Port_Scans/DISCOVERY/'
NMAP_FOLDERS_FULL = '_Scans/Port_Scans/FULL/'
AQUATONE_FOLDERS = '_Scans/Web_App_Enumeration/'
VULN_SCAN_FOLDERS = '_Scans/Vulnerability_Scans/'
ENCRYPTION_CHECK_FOLDERS = '_Scans/Encryption_Check/SSL_TLS_Encryption_Cipher/'
CLEARTEXT_PROTOCOLS_FOLDERS = '_Scans/Encryption_Check/Cleartext_Protocols/'
DEFAULT_LOGINS_FOLDERS = '_Scans/Insecure_Default_Configuration/Default_Logins/'
DOMAINENUM_FOLDERS = '_Scans/Domain_Enumeration/'
SMB_SIGNING_FOLDERS = '_Scans/Insecure_Default_Configuration/SMB_Signing/'
PASS_POLICY_FOLDERS = '_Scans/Password_Policy/'

def cleanup_empty_files(path="."):
    for (dirpath, folder_names, files) in os.walk(path):
        for filename in files:
            if filename not in [STARTED_FILE, RUNNING_FILE, COMPLETE_FILE]:
                file_location = dirpath + '/' + filename  #file location is location is the location of the file
                if os.path.isfile(file_location):
                    if os.path.getsize(file_location) == 0: #Checking if the file is empty or not
                        os.remove(file_location)  #If the file is empty then it is deleted using remove method


def mark_folder_complete(path=".", completion_status=STATUS_CODE_COMPLETE_NOT_RAN):
    os.makedirs(path, exist_ok=True)
    start_file = os.path.join(path, STARTED_FILE)
    if not os.path.isfile(start_file):
        os.system(f'touch {start_file}')

    with open(os.path.join(path, COMPLETE_FILE), 'w', encoding='utf-8') as f:
        f.write(completion_status)


# TODO: Cleanup intermediate-complete files on full-completion
def run_command(command, path=None, write_start_file=False, write_complete_file=False):
    if not write_complete_file:
        # If the command is part of a stage with multiple commands, we don't
        #  want to write the complete file, but we still may want the
        #  intermediate command results
        complete_file = ".intermediate-complete"
    else:
        complete_file = COMPLETE_FILE

    if path:
        started_file = os.path.abspath(os.path.join(path, STARTED_FILE))
        running_file = os.path.abspath(os.path.join(path, RUNNING_FILE))
        failed_file = os.path.abspath(os.path.join(path, FAILED_FILE))
        complete_file = os.path.abspath(os.path.join(path, complete_file))
        os.makedirs(path, exist_ok=True)
    else:
        started_file = os.path.abspath(STARTED_FILE)
        running_file = os.path.abspath(RUNNING_FILE)
        failed_file = os.path.abspath(FAILED_FILE)
        complete_file = os.path.abspath(complete_file)

    print(os.path.abspath(os.curdir))
    full_command = ''
    if write_start_file:
        full_command += f'touch {started_file}; '
    full_command += f'rm {complete_file}; {command}'
    full_command += f'; RESULT="$?"'
    full_command += f'; if [ "$RESULT" -eq 0 ]; then echo "$RESULT" > {complete_file}; else echo "$RESULT" > {failed_file}; fi'
    full_command += f'; rm {running_file}'
    logger.debug(full_command)
    process = subprocess.Popen(full_command, shell=True)
    with open(running_file, 'w', encoding='utf-8') as f:
        f.write(str(process.pid))

    # wait for the process to finish
    process.wait()

def run_gnmap_parser():
    filename = 'Gnmap-Parser.sh'
    for root,dirs,files in os.walk(r'/'):
        for name in files:
            if name == filename:
                parser_location = os.path.abspath(os.path.join(root,name))

    if parser_location:
        run_command(parser_location+' -p', path="./Parsed-Results")
    else:
        raise Exception(f'{filename} not found')


def scoper(rv_num, scope, exclude_file=None):
    if exclude_file:
        run_command(f'nmap -Pn -n -sL -iL {scope} --excludefile {exclude_file} | cut -d " " -f 5 | grep -v "nmap\\|address" > {rv_num}_InScope.txt')
    else:
        run_command(f'nmap -Pn -n -sL -iL {scope} | cut -d " " -f 5 | grep -v "nmap\\|address" > {rv_num}_InScope.txt')


def masscan(rv_num, input_file=None, exclude_file=None):
    if input_file is None:
        raise ValueError("masscan: Masscan requires valid scope. Please provide an input file and try again")

    command = f'masscan -Pn -n -iL {input_file} -p 20,21,22,23,25,53,80,88,110,111,119,123,135,137,139,143,161,389,443,445,636,993,1433,1812,2077,2078,2222,3306,3389,4443,4786,6970,8000,8080,8443 --rate 1500 -oG {rv_num}_masscan.gnmap'
    if exclude_file:
        command += f' --excludefile {exclude_file}'

    home = os.getcwd()
    masscan_folders = rv_num + MASSCAN_FOLDERS
    os.system('mkdir -p '+masscan_folders)
    os.chdir(masscan_folders)
    run_command(command, write_start_file=True)
    run_gnmap_parser()

    with open('./Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt', 'r', encoding="utf-8") as f:
        hosts = f.readlines()

    subnets = set()
    for host in hosts:
        host = host.strip()
        if not '\t' in host:
            continue
        host = host.split('\t')[1]
        host = host.split('.')
        host = '.'.join(host[:3])
        host = host + '.0/24'
        subnets.add(host)

    with open('./discovered-subnets.txt', 'w', encoding="utf-8") as f:
        for net in subnets:
            f.write(net+'\n')

    mark_folder_complete(completion_status="0")
    os.chdir(home)


def discovery(rv_num, input_file=None, exclude_file=None):
    if input_file is None:
        input_file = rv_num + MASSCAN_FOLDERS + "discovered-subnets.txt"
        if not os.path.isfile(input_file):
            raise ValueError("discovery: Discovery scan requires valid scope or a previously run masscan job. Please provide an input file or run a masscan check and try again")

    home = os.getcwd()
    nmap_folders_disc = rv_num+NMAP_FOLDERS_DISC
    os.system('mkdir -p '+nmap_folders_disc)
    if exclude_file:
        run_command('nmap -Pn -n -sS -p 20,21,22,23,25,53,80,88,110,111,119,123,135,137,139,143,161,389,443,445,636,993,1433,1812,2077,2078,2222,3306,3389,4443,4786,6970,8000,8080,8443 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA '+nmap_folders_disc+rv_num+'_DISC -iL '+input_file+' --excludefile '+exclude_file, path=nmap_folders_disc, write_start_file=True)
    else:
        run_command('nmap -Pn -n -sS -p 20,21,22,23,25,53,80,88,110,111,119,123,135,137,139,143,161,389,443,445,636,993,1433,1812,2077,2078,2222,3306,3389,4443,4786,6970,8000,8080,8443 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA '+nmap_folders_disc+rv_num+'_DISC -iL '+input_file, path=nmap_folders_disc, write_start_file=True)
    os.chdir(nmap_folders_disc)
    run_gnmap_parser()
    mark_folder_complete(completion_status="0")
    os.chdir(home)


def get_discovered_hosts_file(rv_num, input_file=None, exclude_file=None):
    hosts = rv_num + NMAP_FOLDERS_DISC + '/Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt'
    if not os.path.isfile(hosts):
        if input_file:
            discovery(rv_num, input_file, exclude_file=exclude_file)
        else:
            raise ValueError("No discovery scans found. Requested scan requires a valid scope. Please provide an input file or run discovery scans and try again")
    return hosts


def full_port(rv_num, input_file=None, exclude_file=None):
    home = os.getcwd()
    if input_file is None:
        input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))

    nmap_folders_full = rv_num+NMAP_FOLDERS_FULL
    os.system('mkdir -p '+nmap_folders_full)
    if exclude_file:
        run_command('nmap -Pn -n -p- --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA '+nmap_folders_full+rv_num+'_FULL'+' '+'-iL '+input_file+' --excludefile '+exclude_file, path=nmap_folders_full, write_start_file=True)
    else:
        run_command('nmap -Pn -n -p- --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA '+nmap_folders_full+rv_num+'_FULL'+' '+'-iL '+input_file, path=nmap_folders_full, write_start_file=True)
    os.chdir(nmap_folders_full)
    run_gnmap_parser()
    mark_folder_complete(completion_status="0")
    os.chdir(home)


def aquatone(rv_num, input_file=None, exclude_file=None):
    home = os.getcwd()
    aquatone_folders = rv_num+AQUATONE_FOLDERS
    if input_file is None:
        input_file = os.path.join(home, rv_num + NMAP_FOLDERS_DISC, 'Parsed-Results/Third-Party/PeepingTom.txt')
        logger.debug(f'aquatone input_file relative to {aquatone_folders}: {input_file}')
        if not os.path.isfile(input_file):
            raise ValueError("aquatone: Aquatone scan requires valid scope or a previously run discovery job. Please provide an input file or run a discovery check and try again")

    # TODO: exclude file is not accounted for here if input is given

    if os.path.isfile(input_file):
        filename = 'aquatone'
        for root,dirs,files in os.walk(r'/'):
            for name in files:
                if name == filename:
                    aquatone_location = os.path.abspath(os.path.join(root,name))
        os.system('mkdir -p '+aquatone_folders)
        os.chdir(aquatone_folders)
        run_command('cat '+input_file+'|'+str(aquatone_location), write_start_file=True, write_complete_file=True)
        os.chdir(home)
    else:
        mark_folder_complete(aquatone_folders)


def vuln_scans(rv_num, input_file=None, exclude_file=None):
    home = os.getcwd()
    if input_file is None:
        input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))

    # TODO: exclude file is not accounted for here if input is given

    vuln_scan_folders = rv_num+VULN_SCAN_FOLDERS
    os.system('mkdir -p '+vuln_scan_folders)
    os.chdir(vuln_scan_folders)

    run_command('nuclei -l '+input_file+' -etags default-login -s critical,high,medium -headless -j -o '+rv_num+'_Vulnerability_Scan.txt', write_start_file=True)
    run_command('cat '+rv_num+'_Vulnerability_Scan.txt |jq > '+rv_num+'_all_findings.json')
    run_command('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"critical"\'|jq > '+rv_num+'_critical_findings.json')
    run_command('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"high"\'|jq > '+rv_num+'_high_findings.json')
    run_command('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"medium"\'|jq > '+rv_num+'_medium_findings.json')
    # Leaving these lines in the event that these findings get incorporated back into the scans
    #run_command('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"low"\'|jq > '+rv_num+'_low_findings.json')
    #run_command('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"info"\'|jq > '+rv_num+'_informational_findings.json')
    #run_command('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"unknown"\'|jq > '+rv_num+'_unknown_findings.json')
    run_command('cat '+rv_num+'_critical_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_critical_affected_hosts.txt')
    run_command('cat '+rv_num+'_high_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_high_affected_hosts.txt')
    run_command('cat '+rv_num+'_medium_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_medium_affected_hosts.txt', write_complete_file=True)
    # Leaving these lines in the event that these findings get incorporated back into the scans
    #run_command('cat '+rv_num+'_low_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_low_affected_hosts.txt')
    #run_command('cat '+rv_num+'_informational_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_informational_affected_hosts.txt', write_complete_file=True)

    run_command('rm -rf .cache')
    cleanup_empty_files()
    os.chdir(home)

def encryption_check(rv_num, input_file=None, exclude_file=None):
    home = os.getcwd()
    nmap_folders = rv_num+NMAP_FOLDERS_DISC
    if input_file is None:
        input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))

    # TODO: Input will clash if nmap folders contain scans from other input
    # TODO: exclude file is not accounted for here if input is given

    cleartext_folder = rv_num + CLEARTEXT_PROTOCOLS_FOLDERS
    os.system('mkdir -p '+cleartext_folder)
    run_command('cp '+home+'/'+ nmap_folders + '/Parsed-Results/Port-Files/20-TCP.txt '+cleartext_folder+' 2>/dev/null', write_start_file=True)
    run_command('cp '+home+'/'+ nmap_folders + '/Parsed-Results/Port-Files/21-TCP.txt '+cleartext_folder+' 2>/dev/null')
    run_command('cp '+home+'/'+ nmap_folders + '/Parsed-Results/Port-Files/23-TCP.txt '+cleartext_folder+' 2>/dev/null')
    run_command('cp '+home+'/'+ nmap_folders + '/Parsed-Results/Port-Files/80-TCP.txt '+cleartext_folder+' 2>/dev/null')
    run_command('cp '+home+'/'+ nmap_folders + '/Parsed-Results/Port-Files/8000-TCP.txt '+cleartext_folder+' 2>/dev/null')
    # Use run_command on last entry so that we get the .complete file
    run_command('cp '+home+'/'+ nmap_folders + '/Parsed-Results/Port-Files/8080-TCP.txt '+cleartext_folder+' 2>/dev/null', path=cleartext_folder)

    ssl_scan_folder = rv_num+ENCRYPTION_CHECK_FOLDERS
    os.system('mkdir -p '+ssl_scan_folder)
    os.chdir(home+'/'+ssl_scan_folder)
    os.system('cat '+home+'/'+ nmap_folders + 'Parsed-Results/Port-Files/443-TCP.txt '+home+'/'+ nmap_folders + 'Parsed-Results/Port-Files/8443-TCP.txt > Scan_Targets.txt 2>/dev/null')
    run_command('sslscan --targets=Scan_Targets.txt|tee '+rv_num+'_SSL_Scan_Results.txt', write_complete_file=True)
    os.chdir(home)

def default_logins(rv_num, input_file=None, exclude_file=None):
    home = os.getcwd()
    if input_file is None:
        input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))

    # TODO: exclude file is not accounted for here if input is given

    default_logins_folders = rv_num+DEFAULT_LOGINS_FOLDERS
    os.makedirs(default_logins_folders, exist_ok=True)

    os.chdir(default_logins_folders)
    run_command('nuclei -l '+input_file+' -tags default-login -headless -j -o '+rv_num+'_Default_Logins.txt', write_start_file=True)
    run_command('cat '+rv_num+'_Default_Logins.txt |jq > '+rv_num+'_all_default_logins_findings.json')
    run_command('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"critical"\'|jq > '+rv_num+'_default_logins_critical_findings.json')
    run_command('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"high"\'|jq > '+rv_num+'_default_logins_high_findings.json')
    run_command('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"medium"\'|jq > '+rv_num+'_default_logins_medium_findings.json')
    run_command('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"low"\'|jq > '+rv_num+'_default_logins_low_findings.json')
    run_command('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"info"\'|jq > '+rv_num+'_default_logins_informational_findings.json')
    run_command('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"unknown"\'|jq > '+rv_num+'_default_logins_unknown_findings.json')
    run_command('cat '+rv_num+'_default_logins_critical_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_critical_affected_hosts.txt')
    run_command('cat '+rv_num+'_default_logins_high_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_high_affected_hosts.txt')
    run_command('cat '+rv_num+'_default_logins_medium_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_medium_affected_hosts.txt')
    run_command('cat '+rv_num+'_default_logins_low_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_low_affected_hosts.txt')
    run_command('cat '+rv_num+'_default_logins_informational_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_informational_affected_hosts.txt', write_complete_file=True)
    
    run_command('rm -rf .cache')
    print(list(os.walk(default_logins_folders)))
    cleanup_empty_files()
    os.chdir(home)

def smb_signing_check(rv_num, input_file=None, exclude_file=None):
    home = os.getcwd()
    if input_file is None:
        input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))

    # TODO: exclude file is not accounted for here if input is given

    smb_signing_folders = rv_num+SMB_SIGNING_FOLDERS
    os.system('mkdir -p '+smb_signing_folders)
    os.chdir(smb_signing_folders)
    run_command('nxc smb '+input_file+' --gen-relay-list '+rv_num+'_SMB_Signing_Disabled.txt --log '+rv_num+'_SMB_Signing_Results.txt', write_start_file=True, write_complete_file=True)
    os.chdir(home)

def all_checks(rv_num, input_file=None, exclude_file=None):
    home = os.getcwd()

    if input_file is None:
        raise ValueError("all_checks: All checks require a valid scope file. Please provide an input file and try again")

    # TODO: Incorporate MASSCAN into all_checks

    ### MASSCAN
    #print(' ')
    #print('Running Masscan Scans...')
    #print(' ')
    #masscan(rv_num, input_file, exclude_file)

    # TODO: Remove input_file from discovery scan once MASSCAN has been accounted for

    ### DISCOVERY
    print(' ')
    print('Running Discovery Scans...')
    print(' ')
    discovery(rv_num, input_file, exclude_file=exclude_file)

    live_targets = home+'/'+rv_num + NMAP_FOLDERS_DISC + '/Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt'

    ### SMB SIGNING
    print(' ')
    print('Running SMB-Signing Scans...')
    print(' ')
    smb_signing_check(rv_num, live_targets)

    ### AQUATONE
    print(' ')
    print('Running Aquatone Web Application Enumeration Scans...')
    print(' ')
    web_targets = home+'/'+rv_num + NMAP_FOLDERS_DISC + '/Parsed-Results/Third-Party/PeepingTom.txt'
    aquatone(rv_num, web_targets)

    ### ENCRYPTION CHECK
    print(' ')
    print('Running Encryption Checks...')
    print(' ')
    encryption_check(rv_num, live_targets)

    ### DEFAULT LOGINS
    print(' ')
    print('Running Default Logins Scans...')
    print(' ')
    default_logins(rv_num, live_targets)

    ### VULN SCANS
    print(' ')
    print('Running Vulnerability Scans...')
    print(' ')
    vuln_scans(rv_num, live_targets)

    ### FULL
    print(' ')
    print('Running Full Port Nmap Scans...')
    print(' ')
    full_port(rv_num, live_targets, exclude_file=exclude_file)

def report_generator(rv_num, customer_name, customer_initials):
    # Define the template file to be used
    template_file = "/opt/MESA-Toolkit/mesa-report-generator/templates/template.html"
    template_directory = "/opt/MESA-Toolkit/mesa-report-generator/templates/"

    #rv_num = rv_num.lower()
    # Create copy of scan data for parsing
    home = os.getcwd()
    os.chdir(home)
    os.system("mkdir -p data")
    os.system(f"cp -r {rv_num}_Scans/ data/{rv_num}-all_checks")
    root_directory = "data/"

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

    # Define locations for input files
    scope_file = f"data/{rv_num}-all_checks/scope.txt"
    exclusions_file = f"data/{rv_num}-all_checks/exclusions.txt"
    discovery_file = f"data/{rv_num}-all_checks/Port_Scans/DISCOVERY/Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt"
    tcp_ports_file = f"data/{rv_num}-all_checks/Port_Scans/FULL/Parsed-Results/Port-Lists/TCP-Ports-List.txt"
    aquatone_urls_file = f"data/{rv_num}-all_checks/Web_App_Enumeration/aquatone_urls.txt"

    # Define a function to count lines in a file and remove leading whitespace
    def count_lines(filename):
        if not os.path.exists(filename):
            return 0
        with open(filename, 'r') as file:
            return len([line.strip() for line in file.readlines()])

    # Define a function to count unique vulnerabilities
    def count_unique_vulns():
        unique_vulns_set = set()
        for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*affected_hosts.txt"):
            with open(file) as f:
                for line in f:
                    vuln_id = line.split('_')[1]
                    unique_vulns_set.add(vuln_id)
        return len(unique_vulns_set)

    # Execute nmap command and count scanned hosts
    try:
        command = f"nmap -Pn -n -sL -iL {scope_file} --excludefile {exclusions_file} | cut -d ' ' -f 5 | grep -v 'nmap\\|address' | wc -l | sed 's/^[[:space:]]*//g'"
        output = subprocess.check_output(command, shell=True, text=True)
        scanned_hosts = int(output.strip())
        os.system(f"nmap -Pn -n -sL -iL {scope_file} --excludefile {exclusions_file} | cut -d ' ' -f 5 | grep -v 'nmap\\|address' > data/{rv_num}-all_checks/consolidated_scope.txt")
    except subprocess.CalledProcessError:
        scanned_hosts = 0

    # Count live hosts
    live_hosts = count_lines(discovery_file)

    # Count unique ports
    unique = count_lines(tcp_ports_file)

    # Count web servers
    web_servers = count_lines(aquatone_urls_file)

    # Count cleartext hosts
    cleartext_hosts = sum(count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Encryption_Check/Cleartext_Protocols/*.txt"))

    # Count default logins
    default_logins = sum(count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Insecure_Default_Configuration/Default_Logins/*affected_hosts.txt"))

    # Count unique vulnerabilities
    unique_vulns = count_unique_vulns()

    # Count critical vulnerabilities
    critical_vulns = sum(count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_critical_affected_hosts.txt"))

    # Count high vulnerabilities
    high_vulns = sum(count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_high_affected_hosts.txt"))

    # Count medium vulnerabilities
    medium_vulns = sum(count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_medium_affected_hosts.txt"))

    # Count low vulnerabilities
    low_vulns = sum(count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_low_affected_hosts.txt"))

    # Count informational vulnerabilities
    info_vulns = sum(count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_informational_affected_hosts.txt"))

    # Count SMB Signing Disabled
    smb_sign_disable = sum(count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Insecure_Default_Configuration/SMB_Signing/*_SMB_Signing_Disabled.txt"))

    # Create a dictionary to store the variables
    variables = {
        "project_name": rv_num,
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
    os.system(f'mkdir -p output/{rv_num}/data output/{rv_num}/report output/{rv_num}/customer_deliverable')
    output_file = f"output/{rv_num}/report/{customer_name}-Report.html"
    with open(output_file, 'w') as output_file:
        output_file.write(rendered_html)

    # Create deliverable zip file to provide to the customer
    os.system(f'cp -r data/{rv_num}-all_checks output/{rv_num}/data')
    os.system(f'cp -r {template_directory}/digest_images output/{rv_num}/data')
    os.system(f'zip -rv {customer_initials}-Customer-Report.zip output/{rv_num}/data "output/{rv_num}/report/{customer_name}-Report.html"')
    os.system(f'mv {customer_initials}-Customer-Report.zip output/{rv_num}/customer_deliverable')

    # Remove variables.json after report generation
    os.remove("variables.json")

    # Remove data directory
    os.system("rm -rf data")