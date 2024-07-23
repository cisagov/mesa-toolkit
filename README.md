# MESA-Toolkit

MESAs (Micro Evaluation Security Assessments) have been crafted to offer organizations insight into their internal security landscape. The MESA-Toolkit serves as the key instrument in achieving this objective by systematically employing a range of security tools. These tools diligently extract valuable information, encompassing details on active services, potential security threats, internal web applications, and more. The resulting data is meticulously organized into directories based on the specific types of information gathered during the tool execution.

It is important to note that MESAs are not designed to furnish a comprehensive understanding of the entire internal environment. Instead, their purpose is to equip organizations with the essential information needed to establish a foundational security posture. This emphasis revolves around safeguarding against commonly exploited misconfigurations and vulnerabilities. MESAs lay the groundwork for organizations to initiate the process of fortifying their security stance, ensuring a proactive defense against prevalent risks.

## Dependencies

The following tools must be installed on the system:
* Aquatone (https://github.com/michenriksen/aquatone)
* Nmap (https://nmap.org/)
* Nuclei (https://github.com/projectdiscovery/nuclei)
* Gnmap-Parser (https://github.com/m1j09830/gnmap-parser)
* NetExec (https://github.com/Pennyw0rth/NetExec)

These dependencies can be installed via the `mesa-install-tools.sh` script. All dependencies including the tool itself will be created in a virtual environment located with the `/opt` directory. 

To install the tool on a Debian 12 virtual machine run the following string:

```
bash mesa-install-tools.sh -vm
```

To install the tool on a Raspberry Pi running Kali run the following string:

```
bash mesa-install-tools.sh -pi
```

## Install
MESA-Toolkit can be installed by cloning this repository and running `pip3 install .` and subsequently executed from PATH with MESA-Toolkit

## Usage

`scoper` - This operation will create an Inscope file which will account for any excluded targets if applicable.  It is highly advised to run scoper first before running any of the subsequent functions.

```
MESA-Toolkit -o scoper -p <Project_Name> -i <Target_File> [-e <Exclude_File>]
```

`masscan` - This operation will perform a masscan discovery scan against the provided scope file and create a separate list of subnets containing live hosts for further evaluation.

```
MESA-Toolkit -o masscan -p <Project_Name> -i <Target_File> [-e <Exclude_File>]
```

`discovery` - This operation will perform an nmap discovery scan against a provided scope file.

```
MESA-Toolkit -o discovery -p <Project_Name> -i <Target_File> [-e <Exclude_File>]
```

`full` - This operation will perform an nmap full port scan against a provided scope file.

```
MESA-Toolkit -o full -p <Project_Name> -i <Target_File> [-e <Exclude_File>]
```

`aquatone` - This operation will perform an aqutone web application enumeration scan against a provided target file.

```
MESA-Toolkit -o aquatone -p <Project_Name> -i <Target_File>
```

`encryption_check` - This operation will perform a discovery scan to identify the exisitence of non encrypted and encrypted protocols within the targeted scope.

```
MESA-Toolkit -o encryption_check -p <Project_Name> -i <Target_File>
```

`default_logins` - This operation will perform automated checks for default login information against web applications and network devices within the provied scope.

```
MESA-Toolkit -o default_logins -p <Project_Name> -i <Target_File>
```

`smb_signing_check` - This operation provides customers with insight into any windows systems lacking smb signing within the tested environment. 

```
MESA-Toolkit -o smb_signing_check -p <Project Name> -i <Target_File>
```

`vuln_scans` - This operation will perform vulnerability scans using nuclei, a template based vulnerability scanner.

```
MESA-Toolkit -o vuln_scans -p <Project_Name> -i <Target_File>
```

`all_checks` - This operation is designed to streamline the testing process by performing all of the previously mentioned tests.

```
MESA-Toolkit -o all_checks -p <Project_Name> -i <Target_File> [-e Exclude_File]
```

`report_generator` - This operation will create a report with hyperlinks referencing the results collected from the scans performed. This operation should only be ran once the following operations have been performed (discovery, aquatone, encryption_check, default_logins, vuln_scans, and smb_signing_check)

```
MESA-Toolkit -o report_generator -p <Project_Name> -cn <Customer_Name> -ci <Customer_Initials>
```

## Development
MESA-Toolkit uses Poetry to manage dependencies. Install from source and setup for development with:
```
git clone https://github.com/m1j09830/MESA-Toolkit
cd MESA-Toolkit
poetry install
poetry run MESA-Toolkit --help
```

## Credits
https://github.com/coffeegist/cookiecutter-app
