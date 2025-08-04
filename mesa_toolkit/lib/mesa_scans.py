#!/usr/bin/python3
#Created by Miguel Rios and Adam Brown
import argparse
import shutil
import sys
import os
import shlex
from datetime import datetime
import getpass
import subprocess
from pathlib import Path
from mesa_toolkit.logger import logger
import json
from jinja2 import Template
import glob
import pdfkit
import re
from typing import Optional, Union

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
EXTENSIONS_TO_REMOVE = [".failed", ".complete", ".intermediate-complete", ".started"]
ROOT_DIRECTORY = 'data/'
LIVE_HOSTS_FILE = 'Port_Scans/DISCOVERY/Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt'

def safe_run_command(command: Union[str, list], shell: bool = True, capture_output: bool = False, 
                    text: bool = True, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """
    Safely run a command using subprocess.run with proper error handling.
    
    Args:
        command: Command to run (string or list)
        shell: Whether to run through shell
        capture_output: Whether to capture stdout/stderr
        text: Whether to return text output
        cwd: Working directory
        
    Returns:
        CompletedProcess object
    """
    try:
        if isinstance(command, str) and shell:
            # For shell commands, we need to be careful about escaping
            result = subprocess.run(command, shell=shell, capture_output=capture_output, 
                                  text=text, cwd=cwd, check=False)
        else:
            # For list commands, no shell needed
            result = subprocess.run(command, shell=False, capture_output=capture_output, 
                                  text=text, cwd=cwd, check=False)
        return result
    except Exception as e:
        logger.error(f"Error running command: {command}, Error: {e}")
        # Return a mock failed result
        return subprocess.CompletedProcess(command, 1, "", str(e))

def safe_mkdir(path: Union[str, Path]) -> bool:
    """
    Safely create directories using pathlib.
    
    Args:
        path: Directory path to create
        
    Returns:
        True if successful, False otherwise
    """
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Error creating directory {path}: {e}")
        return False

def safe_touch_file(file_path: Union[str, Path]) -> bool:
    """
    Safely create a file (equivalent to touch command).
    
    Args:
        file_path: Path to file to create
        
    Returns:
        True if successful, False otherwise
    """
    try:
        Path(file_path).touch()
        return True
    except Exception as e:
        logger.error(f"Error creating file {file_path}: {e}")
        return False

def cleanup_empty_files(path="."):
    for (dirpath, folder_names, files) in os.walk(path):
        for filename in files:
            if filename not in [STARTED_FILE, RUNNING_FILE, COMPLETE_FILE]:
                file_location = dirpath + '/' + filename  #file location is location is the location of the file
                if os.path.isfile(file_location):
                    if os.path.getsize(file_location) == 0: #Checking if the file is empty or not
                        os.remove(file_location)  #If the file is empty then it is deleted using remove method

# Define a safe function to count lines in a file
def safe_count_lines(filename):
    try:
        with open(filename, 'r') as file:
            return len([line.strip() for line in file.readlines()])
    except FileNotFoundError:
        print(f"Warning: File '{filename}' not found. Returning 0.")
        return 0

# Function to remove files with specific extensions
def remove_files_with_extensions(dir_path, extensions):
    for dirpath, dirnames, filenames in os.walk(dir_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            for extension in extensions:
                if filename.endswith(extension):
                    print(f"Removing: {file_path}")
                    os.remove(file_path)

def mark_folder_complete(path=".", completion_status=STATUS_CODE_COMPLETE_NOT_RAN):
    safe_mkdir(path)
    start_file = os.path.join(path, STARTED_FILE)
    if not os.path.isfile(start_file):
        safe_touch_file(start_file)

    with open(os.path.join(path, COMPLETE_FILE), 'w', encoding='utf-8') as f:
        f.write(completion_status)


# TODO: Cleanup intermediate-complete files on full-completion
def run_command(command, path=None, write_start_file=False, write_complete_file=False) -> bool:
    """
    Run a command safely using subprocess with proper file handling.
    
    Returns:
        bool: True if command succeeded, False otherwise
    """
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
        safe_mkdir(path)
    else:
        started_file = os.path.abspath(STARTED_FILE)
        running_file = os.path.abspath(RUNNING_FILE)
        failed_file = os.path.abspath(FAILED_FILE)
        complete_file = os.path.abspath(complete_file)

    print(os.path.abspath(os.curdir))
    
    try:
        # Create start file if requested
        if write_start_file:
            safe_touch_file(started_file)
        
        # Remove complete file if it exists
        if os.path.exists(complete_file):
            os.remove(complete_file)
        
        # Start the process and write PID to running file
        process = subprocess.Popen(command, shell=True)
        with open(running_file, 'w', encoding='utf-8') as f:
            f.write(str(process.pid))

        # Wait for the process to finish
        return_code = process.wait()
        
        # Handle completion
        if return_code == 0:
            with open(complete_file, 'w', encoding='utf-8') as f:
                f.write(str(return_code))
        else:
            with open(failed_file, 'w', encoding='utf-8') as f:
                f.write(str(return_code))
        
        # Remove running file
        if os.path.exists(running_file):
            os.remove(running_file)
        
        logger.debug(f"Command executed: {command}, Return code: {return_code}")
        return return_code == 0
        
    except Exception as e:
        logger.error(f"Error executing command: {command}, Error: {e}")
        # Create failed file
        with open(failed_file, 'w', encoding='utf-8') as f:
            f.write("-1")
        
        # Remove running file if it exists
        if os.path.exists(running_file):
            os.remove(running_file)
            
        return False

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


def scoper(rv_num, scope, exclude_file=None) -> bool:
    """
    Create scope file excluding specified targets.
    
    Returns:
        bool: True if scope creation succeeded, False otherwise
    """
    try:
        if exclude_file:
            return run_command(f'nmap -Pn -n -sL -iL {shlex.quote(scope)} --excludefile {shlex.quote(exclude_file)} | cut -d " " -f 5 | grep -v "nmap\\|address" > {shlex.quote(rv_num)}_InScope.txt')
        else:
            return run_command(f'nmap -Pn -n -sL -iL {shlex.quote(scope)} | cut -d " " -f 5 | grep -v "nmap\\|address" > {shlex.quote(rv_num)}_InScope.txt')
    except Exception as e:
        logger.error(f"Error in scoper function: {e}")
        return False


def masscan(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run masscan port scan.
    
    Returns:
        bool: True if scan succeeded, False otherwise
    """
    if input_file is None:
        logger.error("masscan: Masscan requires valid scope. Please provide an input file and try again")
        return False

    command = f'masscan -Pn -n -iL {shlex.quote(input_file)} -p 20,21,22,23,25,53,80,88,110,111,119,123,135,137,139,143,161,389,443,445,636,993,1433,1812,2077,2078,2222,3306,3389,4443,4786,6970,8000,8080,8443 --rate 1500 -oG {shlex.quote(rv_num)}_masscan.gnmap'
    if exclude_file:
        command += f' --excludefile {shlex.quote(exclude_file)}'

    home = os.getcwd()
    masscan_folders = rv_num + MASSCAN_FOLDERS
    if not safe_mkdir(masscan_folders):
        logger.error(f"Failed to create masscan folders: {masscan_folders}")
        return False
        
    os.chdir(masscan_folders)
    
    try:
        if not run_command(command, write_start_file=True):
            logger.error("Masscan command failed")
            os.chdir(home)
            return False
            
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
        return True
        
    except Exception as e:
        logger.error(f"Error in masscan function: {e}")
        os.chdir(home)
        return False


def discovery(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run nmap discovery scan.
    
    Returns:
        bool: True if scan succeeded, False otherwise
    """
    if input_file is None:
        input_file = rv_num + MASSCAN_FOLDERS + "discovered-subnets.txt"
        if not os.path.isfile(input_file):
            logger.error("discovery: Discovery scan requires valid scope or a previously run masscan job. Please provide an input file or run a masscan check and try again")
            return False

    home = os.getcwd()
    nmap_folders_disc = rv_num+NMAP_FOLDERS_DISC
    if not safe_mkdir(nmap_folders_disc):
        logger.error(f"Failed to create discovery folders: {nmap_folders_disc}")
        return False
        
    try:
        if exclude_file:
            command = f'nmap -Pn -n -sS -p 20,21,22,23,25,53,80,88,110,111,119,123,135,137,139,143,161,389,443,445,636,993,1433,1812,2077,2078,2222,3306,3389,4443,4786,6970,8000,8080,8443 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA {shlex.quote(nmap_folders_disc)}{shlex.quote(rv_num)}_DISC -iL {shlex.quote(input_file)} --excludefile {shlex.quote(exclude_file)}'
        else:
            command = f'nmap -Pn -n -sS -p 20,21,22,23,25,53,80,88,110,111,119,123,135,137,139,143,161,389,443,445,636,993,1433,1812,2077,2078,2222,3306,3389,4443,4786,6970,8000,8080,8443 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA {shlex.quote(nmap_folders_disc)}{shlex.quote(rv_num)}_DISC -iL {shlex.quote(input_file)}'
        
        if not run_command(command, path=nmap_folders_disc, write_start_file=True):
            logger.error("Discovery scan command failed")
            return False
            
        os.chdir(nmap_folders_disc)
        run_gnmap_parser()
        mark_folder_complete(completion_status="0")
        os.chdir(home)
        return True
        
    except Exception as e:
        logger.error(f"Error in discovery function: {e}")
        os.chdir(home)
        return False


def get_discovered_hosts_file(rv_num, input_file=None, exclude_file=None) -> str:
    """
    Get the path to discovered hosts file, running discovery if needed.
    
    Returns:
        str: Path to hosts file
        
    Raises:
        ValueError: If no discovery scans found and no input file provided
    """
    hosts = rv_num + NMAP_FOLDERS_DISC + '/Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt'
    if not os.path.isfile(hosts):
        if input_file:
            if not discovery(rv_num, input_file, exclude_file=exclude_file):
                raise ValueError("Discovery scan failed")
        else:
            raise ValueError("No discovery scans found. Requested scan requires a valid scope. Please provide an input file or run discovery scans and try again")
    return hosts


def full_port(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run full port nmap scan.
    
    Returns:
        bool: True if scan succeeded, False otherwise
    """
    home = os.getcwd()
    if input_file is None:
        try:
            input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))
        except ValueError as e:
            logger.error(f"Full port scan failed: {e}")
            return False

    nmap_folders_full = rv_num+NMAP_FOLDERS_FULL
    if not safe_mkdir(nmap_folders_full):
        logger.error(f"Failed to create full port folders: {nmap_folders_full}")
        return False
        
    try:
        if exclude_file:
            command = f'nmap -Pn -n -p- --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA {shlex.quote(nmap_folders_full)}{shlex.quote(rv_num)}_FULL -iL {shlex.quote(input_file)} --excludefile {shlex.quote(exclude_file)}'
        else:
            command = f'nmap -Pn -n -p- --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA {shlex.quote(nmap_folders_full)}{shlex.quote(rv_num)}_FULL -iL {shlex.quote(input_file)}'
        
        if not run_command(command, path=nmap_folders_full, write_start_file=True):
            logger.error("Full port scan command failed")
            return False
            
        os.chdir(nmap_folders_full)
        run_gnmap_parser()
        mark_folder_complete(completion_status="0")
        os.chdir(home)
        return True
        
    except Exception as e:
        logger.error(f"Error in full_port function: {e}")
        os.chdir(home)
        return False


def aquatone(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run aquatone web application scan.
    
    Returns:
        bool: True if scan succeeded, False otherwise
    """
    home = os.getcwd()
    aquatone_folders = rv_num+AQUATONE_FOLDERS
    if input_file is None:
        input_file = os.path.join(home, rv_num + NMAP_FOLDERS_DISC, 'Parsed-Results/Third-Party/PeepingTom.txt')
        logger.debug(f'aquatone input_file relative to {aquatone_folders}: {input_file}')
        if not os.path.isfile(input_file):
            logger.error("aquatone: Aquatone scan requires valid scope or a previously run discovery job. Please provide an input file or run a discovery check and try again")
            return False

    # TODO: exclude file is not accounted for here if input is given

    if os.path.isfile(input_file):
        filename = 'aquatone'
        aquatone_location = None
        for root,dirs,files in os.walk(r'/'):
            for name in files:
                if name == filename:
                    aquatone_location = os.path.abspath(os.path.join(root,name))
                    break
            if aquatone_location:
                break
                
        if not aquatone_location:
            logger.error("Aquatone binary not found")
            return False
            
        if not safe_mkdir(aquatone_folders):
            logger.error(f"Failed to create aquatone folders: {aquatone_folders}")
            return False
            
        os.chdir(aquatone_folders)
        command = f'cat {shlex.quote(input_file)}|{shlex.quote(str(aquatone_location))}'
        
        try:
            if run_command(command, write_start_file=True, write_complete_file=True):
                os.chdir(home)
                return True
            else:
                logger.error("Aquatone command failed")
                os.chdir(home)
                return False
        except Exception as e:
            logger.error(f"Error running aquatone: {e}")
            os.chdir(home)
            return False
    else:
        mark_folder_complete(aquatone_folders)
        return True


def vuln_scans(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run nuclei vulnerability scans.
    
    Returns:
        bool: True if scan succeeded, False otherwise
    """
    home = os.getcwd()
    if input_file is None:
        try:
            input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))
        except ValueError as e:
            logger.error(f"Vulnerability scan failed: {e}")
            return False

    # TODO: exclude file is not accounted for here if input is given

    vuln_scan_folders = rv_num+VULN_SCAN_FOLDERS
    if not safe_mkdir(vuln_scan_folders):
        logger.error(f"Failed to create vulnerability scan folders: {vuln_scan_folders}")
        return False
        
    os.chdir(vuln_scan_folders)

    try:
        # Run nuclei vulnerability scan
        if not run_command(f'nuclei -l {shlex.quote(input_file)} -etags default-login -s critical,high,medium -headless -j -o {shlex.quote(rv_num)}_Vulnerability_Scan.txt', write_start_file=True):
            logger.error("Nuclei vulnerability scan failed")
            os.chdir(home)
            return False
            
        # Process the results
        run_command(f'cat {shlex.quote(rv_num)}_Vulnerability_Scan.txt |jq > {shlex.quote(rv_num)}_all_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Vulnerability_Scan.txt |grep \'"severity"\':\'"critical"\'|jq > {shlex.quote(rv_num)}_critical_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Vulnerability_Scan.txt |grep \'"severity"\':\'"high"\'|jq > {shlex.quote(rv_num)}_high_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Vulnerability_Scan.txt |grep \'"severity"\':\'"medium"\'|jq > {shlex.quote(rv_num)}_medium_findings.json')
        # Leaving these lines in the event that these findings get incorporated back into the scans
        #run_command(f'cat {shlex.quote(rv_num)}_Vulnerability_Scan.txt |grep \'"severity"\':\'"low"\'|jq > {shlex.quote(rv_num)}_low_findings.json')
        #run_command(f'cat {shlex.quote(rv_num)}_Vulnerability_Scan.txt |grep \'"severity"\':\'"info"\'|jq > {shlex.quote(rv_num)}_informational_findings.json')
        #run_command(f'cat {shlex.quote(rv_num)}_Vulnerability_Scan.txt |grep \'"severity"\':\'"unknown"\'|jq > {shlex.quote(rv_num)}_unknown_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_critical_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_critical_affected_hosts.txt')
        run_command(f'cat {shlex.quote(rv_num)}_high_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_high_affected_hosts.txt')
        run_command(f'cat {shlex.quote(rv_num)}_medium_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_medium_affected_hosts.txt', write_complete_file=True)
        # Leaving these lines in the event that these findings get incorporated back into the scans
        #run_command(f'cat {shlex.quote(rv_num)}_low_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_low_affected_hosts.txt')
        #run_command(f'cat {shlex.quote(rv_num)}_informational_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_informational_affected_hosts.txt', write_complete_file=True)

        safe_run_command('rm -rf .cache')
        cleanup_empty_files()
        os.chdir(home)
        return True
        
    except Exception as e:
        logger.error(f"Error in vuln_scans function: {e}")
        os.chdir(home)
        return False

def encryption_check(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run encryption and cleartext protocol checks.
    
    Returns:
        bool: True if scan succeeded, False otherwise
    """
    home = os.getcwd()
    nmap_folders = rv_num+NMAP_FOLDERS_DISC
    if input_file is None:
        try:
            input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))
        except ValueError as e:
            logger.error(f"Encryption check failed: {e}")
            return False

    # TODO: Input will clash if nmap folders contain scans from other input
    # TODO: exclude file is not accounted for here if input is given

    try:
        cleartext_folder = rv_num + CLEARTEXT_PROTOCOLS_FOLDERS
        if not safe_mkdir(cleartext_folder):
            logger.error(f"Failed to create cleartext folder: {cleartext_folder}")
            return False
            
        # Copy cleartext protocol files
        run_command(f'cp {shlex.quote(home)}/{shlex.quote(nmap_folders)}/Parsed-Results/Port-Files/20-TCP.txt {shlex.quote(cleartext_folder)} 2>/dev/null', write_start_file=True)
        run_command(f'cp {shlex.quote(home)}/{shlex.quote(nmap_folders)}/Parsed-Results/Port-Files/21-TCP.txt {shlex.quote(cleartext_folder)} 2>/dev/null')
        run_command(f'cp {shlex.quote(home)}/{shlex.quote(nmap_folders)}/Parsed-Results/Port-Files/23-TCP.txt {shlex.quote(cleartext_folder)} 2>/dev/null')
        run_command(f'cp {shlex.quote(home)}/{shlex.quote(nmap_folders)}/Parsed-Results/Port-Files/80-TCP.txt {shlex.quote(cleartext_folder)} 2>/dev/null')
        run_command(f'cp {shlex.quote(home)}/{shlex.quote(nmap_folders)}/Parsed-Results/Port-Files/8000-TCP.txt {shlex.quote(cleartext_folder)} 2>/dev/null')
        # Use run_command on last entry so that we get the .complete file
        run_command(f'cp {shlex.quote(home)}/{shlex.quote(nmap_folders)}/Parsed-Results/Port-Files/8080-TCP.txt {shlex.quote(cleartext_folder)} 2>/dev/null', path=cleartext_folder)

        ssl_scan_folder = rv_num+ENCRYPTION_CHECK_FOLDERS
        if not safe_mkdir(ssl_scan_folder):
            logger.error(f"Failed to create SSL scan folder: {ssl_scan_folder}")
            return False
            
        os.chdir(home+'/'+ssl_scan_folder)
        # Combine SSL/TLS port files
        safe_run_command(f'cat {shlex.quote(home)}/{shlex.quote(nmap_folders)}Parsed-Results/Port-Files/443-TCP.txt {shlex.quote(home)}/{shlex.quote(nmap_folders)}Parsed-Results/Port-Files/8443-TCP.txt > Scan_Targets.txt 2>/dev/null')
        
        if not run_command(f'sslscan --targets=Scan_Targets.txt|tee {shlex.quote(rv_num)}_SSL_Scan_Results.txt', write_complete_file=True):
            logger.error("SSL scan failed")
            os.chdir(home)
            return False
            
        os.chdir(home)
        return True
        
    except Exception as e:
        logger.error(f"Error in encryption_check function: {e}")
        os.chdir(home)
        return False

def default_logins(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run default login scans using nuclei.
    
    Returns:
        bool: True if scan succeeded, False otherwise
    """
    home = os.getcwd()
    if input_file is None:
        try:
            input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))
        except ValueError as e:
            logger.error(f"Default logins scan failed: {e}")
            return False

    # TODO: exclude file is not accounted for here if input is given

    default_logins_folders = rv_num+DEFAULT_LOGINS_FOLDERS
    if not safe_mkdir(default_logins_folders):
        logger.error(f"Failed to create default logins folders: {default_logins_folders}")
        return False

    os.chdir(default_logins_folders)
    
    try:
        if not run_command(f'nuclei -l {shlex.quote(input_file)} -tags default-login -headless -j -o {shlex.quote(rv_num)}_Default_Logins.txt', write_start_file=True):
            logger.error("Default logins nuclei scan failed")
            os.chdir(home)
            return False
            
        # Process results
        run_command(f'cat {shlex.quote(rv_num)}_Default_Logins.txt |jq > {shlex.quote(rv_num)}_all_default_logins_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Default_Logins.txt |grep \'"severity"\':\'"critical"\'|jq > {shlex.quote(rv_num)}_default_logins_critical_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Default_Logins.txt |grep \'"severity"\':\'"high"\'|jq > {shlex.quote(rv_num)}_default_logins_high_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Default_Logins.txt |grep \'"severity"\':\'"medium"\'|jq > {shlex.quote(rv_num)}_default_logins_medium_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Default_Logins.txt |grep \'"severity"\':\'"low"\'|jq > {shlex.quote(rv_num)}_default_logins_low_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Default_Logins.txt |grep \'"severity"\':\'"info"\'|jq > {shlex.quote(rv_num)}_default_logins_informational_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_Default_Logins.txt |grep \'"severity"\':\'"unknown"\'|jq > {shlex.quote(rv_num)}_default_logins_unknown_findings.json')
        run_command(f'cat {shlex.quote(rv_num)}_default_logins_critical_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_default_logins_critical_affected_hosts.txt')
        run_command(f'cat {shlex.quote(rv_num)}_default_logins_high_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_default_logins_high_affected_hosts.txt')
        run_command(f'cat {shlex.quote(rv_num)}_default_logins_medium_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_default_logins_medium_affected_hosts.txt')
        run_command(f'cat {shlex.quote(rv_num)}_default_logins_low_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_default_logins_low_affected_hosts.txt')
        run_command(f'cat {shlex.quote(rv_num)}_default_logins_informational_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > {shlex.quote(rv_num)}_default_logins_informational_affected_hosts.txt', write_complete_file=True)
        
        safe_run_command('rm -rf .cache')
        print(list(os.walk(default_logins_folders)))
        cleanup_empty_files()
        os.chdir(home)
        return True
        
    except Exception as e:
        logger.error(f"Error in default_logins function: {e}")
        os.chdir(home)
        return False

def smb_signing_check(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run SMB signing check.
    
    Returns:
        bool: True if scan succeeded, False otherwise
    """
    home = os.getcwd()
    if input_file is None:
        try:
            input_file = os.path.join(home, get_discovered_hosts_file(rv_num, input_file, exclude_file))
        except ValueError as e:
            logger.error(f"SMB signing check failed: {e}")
            return False

    # TODO: exclude file is not accounted for here if input is given

    smb_signing_folders = rv_num+SMB_SIGNING_FOLDERS
    if not safe_mkdir(smb_signing_folders):
        logger.error(f"Failed to create SMB signing folders: {smb_signing_folders}")
        return False
        
    os.chdir(smb_signing_folders)
    
    try:
        if run_command(f'nxc smb {shlex.quote(input_file)} --gen-relay-list {shlex.quote(rv_num)}_SMB_Signing_Disabled.txt --log {shlex.quote(rv_num)}_SMB_Signing_Results.txt', write_start_file=True, write_complete_file=True):
            os.chdir(home)
            return True
        else:
            logger.error("SMB signing check command failed")
            os.chdir(home)
            return False
            
    except Exception as e:
        logger.error(f"Error in smb_signing_check function: {e}")
        os.chdir(home)
        return False

def all_checks(rv_num, input_file=None, exclude_file=None) -> bool:
    """
    Run all security checks.
    
    Returns:
        bool: True if all checks succeeded, False otherwise
    """
    home = os.getcwd()

    if input_file is None:
        logger.error("all_checks: All checks require a valid scope file. Please provide an input file and try again")
        return False

    # TODO: Incorporate MASSCAN into all_checks

    ### MASSCAN
    #print(' ')
    #print('Running Masscan Scans...')
    #print(' ')
    #if not masscan(rv_num, input_file, exclude_file):
    #    logger.error("Masscan failed")
    #    return False

    # TODO: Remove input_file from discovery scan once MASSCAN has been accounted for

    ### DISCOVERY
    print(' ')
    print('Running Discovery Scans...')
    print(' ')
    if not discovery(rv_num, input_file, exclude_file=exclude_file):
        logger.error("Discovery scan failed")
        return False

    live_targets = home+'/'+rv_num + NMAP_FOLDERS_DISC + '/Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt'

    ### SMB SIGNING
    print(' ')
    print('Running SMB-Signing Scans...')
    print(' ')
    if not smb_signing_check(rv_num, live_targets):
        logger.warning("SMB signing check failed, continuing with other scans")

    ### AQUATONE
    print(' ')
    print('Running Aquatone Web Application Enumeration Scans...')
    print(' ')
    web_targets = home+'/'+rv_num + NMAP_FOLDERS_DISC + '/Parsed-Results/Third-Party/PeepingTom.txt'
    if not aquatone(rv_num, web_targets):
        logger.warning("Aquatone scan failed, continuing with other scans")

    ### ENCRYPTION CHECK
    print(' ')
    print('Running Encryption Checks...')
    print(' ')
    if not encryption_check(rv_num, live_targets):
        logger.warning("Encryption check failed, continuing with other scans")

    ### DEFAULT LOGINS
    print(' ')
    print('Running Default Logins Scans...')
    print(' ')
    if not default_logins(rv_num, live_targets):
        logger.warning("Default logins scan failed, continuing with other scans")

    ### VULN SCANS
    print(' ')
    print('Running Vulnerability Scans...')
    print(' ')
    if not vuln_scans(rv_num, live_targets):
        logger.warning("Vulnerability scan failed, continuing with other scans")

    ### FULL
    print(' ')
    print('Running Full Port Nmap Scans...')
    print(' ')
    if not full_port(rv_num, live_targets, exclude_file=exclude_file):
        logger.warning("Full port scan failed")
        
    return True

def report_generator(rv_num, customer_name, customer_initials) -> bool:
    """
    Generate HTML and PDF reports.
    
    Returns:
        bool: True if report generation succeeded, False otherwise
    """
    # Define the template file to be used
    template_file = "/opt/MESA-Toolkit/mesa-report-generator/templates/template.html"
    template_directory = "/opt/MESA-Toolkit/mesa-report-generator/templates/"

    #rv_num = rv_num.lower()
    # Create copy of scan data for parsing
    home = os.getcwd()
    os.chdir(home)
    
    try:
        safe_mkdir("data")
        safe_run_command(f"cp -r {shlex.quote(rv_num)}_Scans/ data/{shlex.quote(rv_num)}-all_checks")

        # Call the function to remove files with specified extensions
        remove_files_with_extensions(ROOT_DIRECTORY, EXTENSIONS_TO_REMOVE)

        # Define locations for input files
        scope_file = f"data/{rv_num}-all_checks/scope.txt"
        exclusions_file = f"data/{rv_num}-all_checks/exclusions.txt"
        discovery_file = f"data/{rv_num}-all_checks/{LIVE_HOSTS_FILE}"
        tcp_ports_file = f"data/{rv_num}-all_checks/Port_Scans/FULL/Parsed-Results/Port-Lists/TCP-Ports-List.txt"
        aquatone_urls_file = f"data/{rv_num}-all_checks/Web_App_Enumeration/aquatone_urls.txt"

        # Define a function to count unique vulnerabilities
        def count_unique_vulns():
            unique_vulns_set = set()
            for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*affected_hosts.txt"):
                with open(file) as f:
                    for line in f:
                        vuln_id = line.split(' ')[1]
                        unique_vulns_set.add(vuln_id)
            return len(unique_vulns_set)

        # Execute nmap command and count scanned hosts
        try:
            command = f"nmap -Pn -n -sL -iL {shlex.quote(scope_file)} --excludefile {shlex.quote(exclusions_file)} | cut -d ' ' -f 5 | grep -v 'nmap\\|address' | wc -l | sed 's/^[[:space:]]*//g'"
            output = subprocess.check_output(command, shell=True, text=True)
            scanned_hosts = int(output.strip())
            safe_run_command(f"nmap -Pn -n -sL -iL {shlex.quote(scope_file)} --excludefile {shlex.quote(exclusions_file)} | cut -d ' ' -f 5 | grep -v 'nmap\\|address' > data/{shlex.quote(rv_num)}-all_checks/consolidated_scope.txt")
        except subprocess.CalledProcessError:
            scanned_hosts = 0

        # Count live hosts
        live_hosts = safe_count_lines(discovery_file)

        # Count unique ports
        unique = safe_count_lines(tcp_ports_file)

        # Count web servers
        web_servers = safe_count_lines(aquatone_urls_file)

        # Count cleartext hosts
        cleartext_hosts = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Encryption_Check/Cleartext_Protocols/*.txt"))

        # Count default logins
        default_logins = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Insecure_Default_Configuration/Default_Logins/*affected_hosts.txt"))

        # Count unique vulnerabilities
        unique_vulns = count_unique_vulns()

        # Count critical vulnerabilities
        critical_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_critical_affected_hosts.txt"))

        # Count high vulnerabilities
        high_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_high_affected_hosts.txt"))

        # Count medium vulnerabilities
        medium_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_medium_affected_hosts.txt"))

        # Count low vulnerabilities
        low_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_low_affected_hosts.txt"))

        # Count informational vulnerabilities
        info_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_informational_affected_hosts.txt"))

        # Count SMB Signing Disabled
        smb_sign_disable = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Insecure_Default_Configuration/SMB_Signing/*_SMB_Signing_Disabled.txt"))

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
            with open(template_file, 'r') as template_file_obj:
                template_content = template_file_obj.read()
        except FileNotFoundError:
            logger.error(f"Error: Template file '{template_file}' not found.")
            return False

        try:
            with open('variables.json', 'r') as json_file:
                data = json.load(json_file)
        except FileNotFoundError:
            logger.error("Error: Data file 'variables.json' not found.")
            return False

        # Render the template with the data
        template = Template(template_content)
        rendered_html = template.render(data)

        # Write the rendered HTML to the output file
        safe_mkdir(f'output/{rv_num}/data')
        safe_mkdir(f'output/{rv_num}/report')
        safe_mkdir(f'output/{rv_num}/customer_deliverable')
        
        output_file = f"output/{rv_num}/report/{customer_name}-Report.html"
        with open(output_file, 'w') as output_file_obj:
            output_file_obj.write(rendered_html)
       
        # Store the cwd
        current_dir = os.getcwd()

        # Create a modified, temporary version of the html file that was just created to convert into a pdf
        # The head commands are grabbing applicable sections of the html file, and discarding the rest
        safe_run_command(f'head -n 149 {shlex.quote(f"{current_dir}/output/{rv_num}/report/{customer_name}-Report.html")} > tmp.html')
        safe_run_command(f'tail -n +153 {shlex.quote(f"{current_dir}/output/{rv_num}/report/{customer_name}-Report.html")} >> tmp.html')

        #safe_run_command(f'head -n 230 {shlex.quote(f"{current_dir}/output/{rv_num}/report/{customer_name}-Report.html")} > tmp.html')
        safe_run_command('echo "  </body>" >> tmp.html')
        safe_run_command('echo "</html>" >> tmp.html')
        

        # Create a pdf based off of the modified html file
        safe_run_command(f'wkhtmltopdf --enable-local-file-access --disable-javascript --log-level error tmp.html {shlex.quote(f"{current_dir}/output/{rv_num}/report/{customer_name}-Report.pdf")}')
        # Modify the paths in the pdf file to be relative and not specific to root
        safe_run_command(f"sed -i 's|file:///root/.mesa/|../|g' {shlex.quote(f'{current_dir}/output/{rv_num}/report/{customer_name}-Report.pdf')}")
        # Remove the temporary html file now that the pdf is fully created
        safe_run_command('rm tmp.html')

        # Create deliverable zip file to provide to the customer
        safe_run_command(f'cp -r data/{shlex.quote(rv_num)}-all_checks output/{shlex.quote(rv_num)}/data')
        safe_run_command(f'cp -r {shlex.quote(template_directory)}/digest_images output/{shlex.quote(rv_num)}/data')
        safe_run_command(f'zip -rv {shlex.quote(customer_initials)}-Customer-Report.zip output/{shlex.quote(rv_num)}/data {shlex.quote(f"output/{rv_num}/report/{customer_name}-Report.html")} {shlex.quote(f"output/{rv_num}/report/{customer_name}-Report.pdf")}')
        safe_run_command(f'mv {shlex.quote(customer_initials)}-Customer-Report.zip output/{shlex.quote(rv_num)}/customer_deliverable')

        # Remove variables.json after report generation
        os.remove("variables.json")

        # Remove data directory
        safe_run_command("rm -rf data")
        
        return True
        
    except Exception as e:
        logger.error(f"Error in report_generator function: {e}")
        return False

def json_generator(rv_num, customer_name, customer_initials) -> bool:
    """
    Generate JSON data files.
    
    Returns:
        bool: True if JSON generation succeeded, False otherwise
    """
    # Define the template file to be used
    template_file = "/opt/MESA-Toolkit/mesa-report-generator/templates/template.html"
    template_directory = "/opt/MESA-Toolkit/mesa-report-generator/templates/"

    # Create copy of scan data for parsing
    home = os.getcwd()
    os.chdir(home)
    
    try:
        safe_mkdir("data")
        safe_run_command(f"cp -r {shlex.quote(rv_num)}_Scans/ data/{shlex.quote(rv_num)}-all_checks")

        remove_files_with_extensions(ROOT_DIRECTORY, EXTENSIONS_TO_REMOVE)

        # Define locations for input files
        scope_file = f"data/{rv_num}-all_checks/scope.txt"
        exclusions_file = f"data/{rv_num}-all_checks/exclusions.txt"
        discovery_file = f"data/{rv_num}-all_checks/{LIVE_HOSTS_FILE}"
        tcp_ports_file = f"data/{rv_num}-all_checks/Port_Scans/FULL/Parsed-Results/Port-Lists/TCP-Ports-List.txt"
        aquatone_urls_file = f"data/{rv_num}-all_checks/Web_App_Enumeration/aquatone_urls.txt"

        # Execute nmap command and count scanned hosts
        try:
            command = f"nmap -Pn -n -sL -iL {shlex.quote(scope_file)} --excludefile {shlex.quote(exclusions_file)} | cut -d ' ' -f 5 | grep -v 'nmap\\|address' | wc -l | sed 's/^[[:space:]]*//g'"
            output = subprocess.check_output(command, shell=True, text=True)
            scanned_hosts = int(output.strip())
            safe_run_command(f"nmap -Pn -n -sL -iL {shlex.quote(scope_file)} --excludefile {shlex.quote(exclusions_file)} | cut -d ' ' -f 5 | grep -v 'nmap\\|address' > data/{shlex.quote(rv_num)}-all_checks/consolidated_scope.txt")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing nmap command: {e}")
            scanned_hosts = 0
        
        # Safely count file-based metrics
        live_hosts = safe_count_lines(discovery_file)
        unique = safe_count_lines(tcp_ports_file)
        web_servers = safe_count_lines(aquatone_urls_file)

        # Safely sum values for multiple files
        cleartext_hosts = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Encryption_Check/Cleartext_Protocols/*.txt"))
        default_logins = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Insecure_Default_Configuration/Default_Logins/*affected_hosts.txt"))
        unique_vulns = len(set(line.split('-')[1] for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*affected_hosts.txt") for line in open(file, 'r', errors='ignore')))

        critical_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_critical_affected_hosts.txt"))
        high_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_high_affected_hosts.txt"))
        medium_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_medium_affected_hosts.txt"))
        low_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_low_affected_hosts.txt"))
        info_vulns = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Vulnerability_Scans/*_informational_affected_hosts.txt"))
        smb_sign_disable = sum(safe_count_lines(file) for file in glob.glob(f"data/{rv_num}-all_checks/Insecure_Default_Configuration/SMB_Signing/*_SMB_Signing_Disabled.txt"))

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
            with open(template_file, 'r') as template_file_obj:
                template_content = template_file_obj.read()
        except FileNotFoundError:
            logger.error(f"Error: Template file '{template_file}' not found.")
            return False

        try:
            with open('variables.json', 'r') as json_file:
                data = json.load(json_file)
        except FileNotFoundError:
            logger.error("Error: Data file 'variables.json' not found.")
            return False

        # Create the proper directories for output files
        safe_mkdir(f'output/{rv_num}/data')
        safe_mkdir(f'output/{rv_num}/json') 
        safe_mkdir(f'output/{rv_num}/customer_deliverable')

        # Create deliverable zip file to provide to the customer
        safe_run_command(f'cp -r data/{shlex.quote(rv_num)}-all_checks output/{shlex.quote(rv_num)}/data')
        safe_run_command(f'cp -r {shlex.quote(template_directory)}/digest_images output/{shlex.quote(rv_num)}/data')

        default_dir = f'output/{rv_num}/data/{rv_num}-all_checks'

        generate_json_file(f'output/{rv_num}/json/{rv_num}-mesa-data.json', default_dir, rv_num)

        # Zip everything together and move it into the proper directory to eventually be downloaded by the user
        safe_run_command(f'zip -rv {shlex.quote(rv_num)}-mesa-json-data.zip output/{shlex.quote(rv_num)}/data {shlex.quote(f"output/{rv_num}/json/{rv_num}-mesa-data.json")}')
        safe_run_command(f'mv {shlex.quote(rv_num)}-mesa-json-data.zip output/{shlex.quote(rv_num)}/customer_deliverable')

        # Remove variables.json after report generation
        os.remove("variables.json")

        # Remove data directory
        safe_run_command("rm -rf data")
        
        return True
        
    except Exception as e:
        logger.error(f"Error in json_generator function: {e}")
        return False

# A helper function to see if a string is located in a file
def located_in_file(file_to_read, string_to_find):
    with open(file_to_read) as f:
        if string_to_find in f.read():
            f.close()
            return "True" # If found, return True (ends the function)
    f.close()
    return "False" # If not found by the end, the input string is not located in the file. Return False

# Returns a count of live hosts from the port scan
def get_live_hosts(default_dir):
    # Open the file that lists live hosts
    try:
        with open(rf'{default_dir}/{LIVE_HOSTS_FILE}', 'r') as file:
            lines = file.read().splitlines()
            count = 0
            for element in lines: # Loop through and increment the count of live hosts
                count = count + 1
        file.close()
        return count # Return the final count
    except FileNotFoundError: # If there is no live hosts file, we can safely assume the count is 0
        return 0

# Returns a list of dictionaries for the ports and their associated counts, grouped by third party service
def third_party_json_generate(default_dir):
    json_return_data = [] # A variable that will store the data this function will ultimately return
    found_port = False # Whether the port was already included in the current output. Is false until found

    # Looping through each third party service file that was scanned for
    for filename in os.listdir(f'{default_dir}/Port_Scans/FULL/Parsed-Results/Third-Party'):
        with open(rf'{default_dir}/Port_Scans/FULL/Parsed-Results/Third-Party/{filename}', 'r') as file:
            ports_list = [] # Resetting the list of ports for the new third party service
            lines = file.read().splitlines()

            for finding in lines: # Loop through the lines in the current third party service file
                match = re.match(r'(\w+)://([\d\.]+):(\d+)', finding) # Split the url data into its 3 components
                for entry in ports_list: # For every port / http(s) combination documented so far
                    if entry['port'] == match.group(3): # If the port already exists, check if this is http or https
                        if match.group(1) == 'http': # If it is http, increment the http count
                            if 'http_count' in entry: # Increment if the http count exists
                                entry['http_count'] = entry['http_count'] + 1
                            else: # Create the http count if it doesn't exist
                                entry['http_count'] = 1
                        else: # If it is https, increment the https count
                            if 'https_count' in entry: # Increment if the https count exists
                                entry['https_count'] = entry['https_count'] + 1
                            else: # Create the https count if it doesn't exist
                                entry['https_count'] = 1
                        found_port = True

                if found_port == False: # If the port did not already exist, add it with the appropriate count
                    if match.group(1) == 'http': # If the port has http
                        tmp_dict = { 'port':match.group(3), 'http_count':1 }
                    else: # Otherwise, if the port has https
                        tmp_dict = { 'port':match.group(3), 'https_count':1 }
                    ports_list.append(tmp_dict.copy()) # Append the temporary value to the list of ports
                    tmp_dict.clear() # Clear for the next iteration
                found_port = False # Reset the value

            # Ordering the port results so they appear in descending order in the json file
            sorted_ports_list = sorted(ports_list, key=lambda x: int(x.get('port', 99999999)))
            filename_trimmed = filename.removesuffix('.txt').lower() # Trim the file type and make it lowercase
            data_tmp = { filename_trimmed:sorted_ports_list.copy() } # Add the current third party service data to a tmp var
            ports_list.clear() # Clear the list of ports for the next iteration (next third party service)
            json_return_data.append(data_tmp.copy()) # Append the collected data to the json to return
        file.close()

    # Sorting the json return data before returning
    json_return_data_sorted = sorted(json_return_data, key=lambda x: list(x.keys())[0])

    return json_return_data_sorted # Returning the third party data

    # Add the vulnerability_results to the main dictionary
    data["vulnerability_results"] = vulnerability_results

def vuln_data_json_generate(default_dir):
    json_return_data = []  # A variable to store the data this function will return

    # Looping through each text file in the specified directory
    for filename in os.listdir(f'{default_dir}/Vulnerability_Scans'):
        # Process files that have '.txt' extension and contain 'affected_hosts' in the name
        if filename.endswith('.txt') and 'affected_hosts' in filename:
            with open(rf'{default_dir}/Vulnerability_Scans/{filename}', 'r') as file:
                vuln_dict = {}  # Dictionary to store counts of vulnerabilities

                lines = file.read().splitlines()

                for finding in lines:  # Loop through the lines in the current vulnerability scan file
                    # Split the line by ' - ' delimiter and extract relevant fields
                    parts = finding.split(' - ')
                    if len(parts) >= 2:
                        severity = parts[0].strip()  # First field: severity (e.g., 'medium')
                        description = parts[1].strip()  # Second field: vulnerability description (e.g., 'SMB Signing Not Required')

                        # Combine severity and description as a unique key
                        vuln_key = f"{severity} - {description}"

                        # Increment the count if this vulnerability already exists, otherwise set it to 1
                        if vuln_key in vuln_dict:
                            vuln_dict[vuln_key] += 1
                        else:
                            vuln_dict[vuln_key] = 1

                # Convert the vulnerability dictionary to a list of dictionaries with count, severity, and description
                vuln_list = [{'severity': key.split(' - ')[0], 'description': key.split(' - ')[1], 'count': count}
                             for key, count in vuln_dict.items()]

                filename_trimmed = filename.removesuffix('.txt').lower()  # Trim the file extension and convert to lowercase
                data_tmp = {filename_trimmed: vuln_list.copy()}  # Store the vulnerability data for the current file
                json_return_data.append(data_tmp.copy())  # Append the data to the final JSON structure

            file.close()

    return json_return_data  # Return the generated JSON structure

def default_login_data_json_generate(default_dir):
    json_return_data = []  # A variable to store the data this function will return

    # Looping through each text file in the specified directory
    for filename in os.listdir(f'{default_dir}/Insecure_Default_Configuration/Default_Logins'):
        # Process files that have '.txt' extension and contain 'affected_hosts' in the name
        if filename.endswith('.txt') and 'affected_hosts' in filename:
            with open(rf'{default_dir}/Insecure_Default_Configuration/Default_Logins/{filename}', 'r') as file:
                vuln_dict = {}  # Dictionary to store counts of vulnerabilities

                lines = file.read().splitlines()

                for finding in lines:  # Loop through the lines in the current vulnerability scan file
                    # Split the line by ' - ' delimiter and extract relevant fields
                    parts = finding.split(' - ')
                    if len(parts) >= 2:
                        severity = parts[0].strip()  # First field: severity (e.g., 'medium')
                        description = parts[1].strip()  # Second field: vulnerability description (e.g., 'SMB Signing Not Required')

                        # Combine severity and description as a unique key
                        vuln_key = f"{severity} - {description}"

                        # Increment the count if this vulnerability already exists, otherwise set it to 1
                        if vuln_key in vuln_dict:
                            vuln_dict[vuln_key] += 1
                        else:
                            vuln_dict[vuln_key] = 1

                # Convert the vulnerability dictionary to a list of dictionaries with count, severity, and description
                vuln_list = [{'severity': key.split(' - ')[0], 'description': key.split(' - ')[1], 'count': count}
                             for key, count in vuln_dict.items()]

                filename_trimmed = filename.removesuffix('.txt').lower()  # Trim the file extension and convert to lowercase
                data_tmp = {filename_trimmed: vuln_list.copy()}  # Store the vulnerability data for the current file
                json_return_data.append(data_tmp.copy())  # Append the data to the final JSON structure

            file.close()

    return json_return_data  # Return the generated JSON structure

# Returns a list of dictionaries for the ports and their associated counts, grouped by cleartext protocol
def port_data_json_generate(default_dir):
    json_return_data = [] # A variable that will store the data this function will ultimately return
    found_port = False # Whether the port was already included in the current output. Is false until found

    # Looping through each cleartext protocol file that was scanned for
    for filename in os.listdir(f'{default_dir}/Port_Scans/FULL/Parsed-Results/Port-Matrix'):
        with open(rf'{default_dir}/Port_Scans/FULL/Parsed-Results/Port-Matrix/{filename}', 'r') as file:
            ports_list = [] # Resetting the list of ports for the new cleartext protocol
            lines = file.read().splitlines()

            for finding in lines: # Loop through the lines in the current cleartext protocol file
                data = finding.split(',') # Split the file data by comma
                for entry in ports_list: # For every port / count combination documented so far
                    if entry['port'] == data[2]: # If the port already exists, increment its count
                        entry['count'] = entry['count'] + 1
                        found_port = True
                if found_port == False: # If the port didn't already exist, add it with a count of 1
                    tmp_dict = { 'port':data[2], 'count':1 }
                    ports_list.append(tmp_dict.copy())
                    tmp_dict.clear()
                found_port = False # Reset this value for the next iteration

            # Ordering the port results so they appear in descending order in the output json file
            sorted_ports_list = sorted(ports_list, key=lambda x: int(x['port']))
            # Trimming the file name to only include the current cleartext protocol
            filename_trimmed = filename.removesuffix('-Services-Matrix.csv').lower()
            data_tmp = { # Saving the data for the current cleartext protocol in a tmp dictionary
                filename_trimmed:sorted_ports_list.copy()
            }

            ports_list.clear() # Clear the port list for the next iteration
            json_return_data.append(data_tmp) # Add the current data to the list of return data
        file.close()

    # Sorting the json return data before returning
    json_return_data_sorted = sorted(json_return_data, key=lambda x: list(x.keys())[0])

    return json_return_data_sorted # Returning all of the cleartext protocol data

def smb_data_json_generate(default_dir):
    json_return_data = {}  # Creating the dictionary that will be returned later
    current_count = 0  # Keeps track of the current value being counted

    # Use glob to find all files that end with 'SMB_Signing_Disabled.txt'
    smb_files = glob.glob(f'{default_dir}/Insecure_Default_Configuration/SMB_Signing/*_SMB_Signing_Disabled.txt')

    if smb_files:  # Check if any files are found
        for filename in smb_files:
            try:
                with open(filename, 'r') as file:
                    lines = file.read().splitlines()  # Gets the lines from the file
                    current_count += len(lines)  # Add the count of lines from this file to the total count
            except FileNotFoundError:
                pass  # If for some reason a file is missing, just skip it

        json_return_data['smb_signing_disabled'] = current_count  # Add the total count to the return data
    else:
        # If no files are found, set count to 0
        json_return_data['smb_signing_disabled'] = 0

    return json_return_data

# A function that collects and returns the host data from a mesa port scan
def host_data_json_generate(default_dir):
    json_return_data = {} # Creating the dictionary that will be returned later
    current_count = 0 # Keeps track of the current value being counted

    # Open the file containing the hosts with open ports
    try:
        with open(rf'{default_dir}/{LIVE_HOSTS_FILE}', 'r') as file:
            lines = file.read().splitlines() # Gets the lines from the file
            for finding in lines: # Loops through the lines and keeps track of the count
                current_count = current_count + 1
            json_return_data['hosts_with_open_ports'] = current_count # Add the current count to the return data
            current_count = 0
        file.close()
    except FileNotFoundError: # If the file doesn't exist, 0 is the default count
        json_return_data['hosts_with_open_ports'] = 0

    # Loop through the filenames in the directory of host properties
    for filename in os.listdir(f'{default_dir}/Port_Scans/FULL/Parsed-Results/Host-Type'):
        # Read all of the files
        with open(rf'{default_dir}/Port_Scans/FULL/Parsed-Results/Host-Type/{filename}', 'r') as file:
            lines = file.read().splitlines()
            for finding in lines: # Loop through the lines and increment the current count
                current_count = current_count + 1
            key_name = filename.removesuffix('.txt').lower() + '_count' # Get the name of the key based off of the file name
            json_return_data[key_name] = current_count # Add the current count to the return data
            current_count = 0 # Reset the current count for the next loop
        file.close()

    return json_return_data # Return the collected / formatted data

def consolidated_scope_get_count(default_dir):
    current_count = 0
    try:
        with open(rf'{default_dir}/consolidated_scope.txt', 'r') as file:
            lines = file.read().splitlines()
            for address in lines:
                current_count = current_count + 1
            return current_count
    except FileNotFoundError:
        return current_count

def get_current_fiscal_year():
    """
    Calculate the current federal fiscal year based on the current date.
    Federal fiscal year runs from October 1st through September 30th.
    
    Returns:
        str: The current fiscal year as a string (e.g., "2026")
    """
    now = datetime.now()
    current_year = now.year
    current_month = now.month
    
    # If we're in October, November, or December, it's the next calendar year's fiscal year
    if current_month >= 10:
        fiscal_year = current_year + 1
    else:
        # If we're in January through September, it's the current calendar year's fiscal year
        fiscal_year = current_year
    
    return str(fiscal_year)

# The main function of this script that calls all other generation functions to create the json output
def generate_json_file(filename, default_dir, rv_num):
    try:
        # Generating the json output data using the above functions
        output_json = {
            "type": "Micro Evaluation Security Assessment (MESA)",
            "id": rv_num,
            "fiscal_year": get_current_fiscal_year(),
            "sector": "",
            "critical_infrastructure_sector": "",
            "critical_infrastructure_subsector": "",
            "testing_start_date": "",
            "testing_completion_date": "",
            "state": "",
        }

        # Safely calling helper functions and assigning default values on failure
        try:
            output_json["consolidated_scope_count"] = consolidated_scope_get_count(default_dir)
        except Exception as e:
            print(f"Warning: Failed to get consolidated scope count. Error: {e}")
            output_json["consolidated_scope_count"] = 0

        try:
            output_json["live_hosts"] = get_live_hosts(default_dir)
        except Exception as e:
            print(f"Warning: Failed to get live hosts count. Error: {e}")
            output_json["live_hosts"] = 0

        try:
            output_json["host_data"] = host_data_json_generate(default_dir)
        except Exception as e:
            print(f"Warning: Failed to generate host data. Error: {e}")
            output_json["host_data"] = []

        try:
            output_json["protocols"] = port_data_json_generate(default_dir)
        except Exception as e:
            print(f"Warning: Failed to generate protocol data. Error: {e}")
            output_json["protocols"] = []

        try:
            output_json["web_applications"] = third_party_json_generate(default_dir)
        except Exception as e:
            print(f"Warning: Failed to generate web applications data. Error: {e}")
            output_json["web_applications"] = []

        try:
            output_json["default_logins"] = default_login_data_json_generate(default_dir)
        except Exception as e:
            print(f"Warning: Failed to generate default login data. Error: {e}")
            output_json["default_logins"] = []

        try:
            output_json["vulnerability_scans"] = vuln_data_json_generate(default_dir)
        except Exception as e:
            print(f"Warning: Failed to generate vulnerability data. Error: {e}")
            output_json["vulnerability_scans"] = []

        try:
            output_json["smb_signing"] = smb_data_json_generate(default_dir)
        except Exception as e:
            print(f"Warning: Failed to generate smb signing data. Error: {e}")
            output_json["smb_signing"] = []

        # Format the generated JSON data to JSON format
        formatted_json = json.dumps(output_json, indent=2)

        # Ensure the output file exists and write the JSON data
        safe_touch_file(filename)
        with open(filename, "w") as f:
            f.write(formatted_json)

    except Exception as e:
        print(f"Error: Failed to generate JSON file. Error: {e}")
