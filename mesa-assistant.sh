#! /bin/bash

function scoper() {
    read -p "Enter the assessment number: " -r asmtnum
    read -p "Enter path to line seperated scope ranges: " -i "" -e scope
    read -p "Are there any IPs that must be excluded? (y or n): " -r exclude
    if [ $exclude == y ]; then
        read -p "Enter path to exclude scope file: " -i "" -e exclude_scope
        screen -S ${asmtnum} -d -m source /opt/MESA-venv/bin/activate && MESA-Toolkit -o scoper -i ${scope} -e ${exclude_scope} -p ${asmtnum}
    else
        screen -S ${asmtnum} -d -m source /opt/MESA-venv/bin/activate && MESA-Toolkit -o scoper -i ${scope} -p ${asmtnum}
    fi
}

function discovery() {
    read -p "Enter the assessment number: " -r asmtnum
    read -p "Enter path to inscope file: " -i "" -e scope
    read -p "Are there any IPs that must be excluded? (y or n): " -r exclude
#    read -p "Would you like to run a multithreaded scan? (y or n): " -r multithread
    if [ $exclude == y ]; then
        read -p "Enter path to exclude scope file: " -i "" -e exclude_scope
        MESA-Toolkit -o discovery -i ${scope} -p ${asmtnum} -e ${exclude_scope}
    else
        MESA-Toolkit -o discovery -i ${scope} -p ${asmtnum}
    fi
# The following section is experimental and is not ready for production. Do not uncomment without understanding the potential ramifications.
#        if [ $multithread == y ]; then
#            split -n l/10 -d ${scope} ${asmtnum}-DISC
#            home=$(pwd)
#            mkdir -p ${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Scans
#            mkdir -p ${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Results
#            mv ${asmtnum}-DISC0* ${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Scans
#            cd ${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Scans
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC00 -p ${asmtnum}-DISC00 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC01 -p ${asmtnum}-DISC01 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC02 -p ${asmtnum}-DISC02 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC03 -p ${asmtnum}-DISC03 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC04 -p ${asmtnum}-DISC04 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC05 -p ${asmtnum}-DISC05 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC06 -p ${asmtnum}-DISC06 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC07 -p ${asmtnum}-DISC07 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC08 -p ${asmtnum}-DISC08 -e ${exclude_scope} &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC09 -p ${asmtnum}-DISC09 -e ${exclude_scope} &
#            top
#            cp ${asmtnum}-DISC0*/Port_Scans/DISCOVERY/${asmtnum}* ${home}/${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Results/
#            cd ${home}/${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Results/
#            parser=$(locate Gnmap-Parser.sh)
#            bash ${parser} -p
#        else
#            MESA-Toolkit -o discovery -i ${scope} -p ${asmtnum} -e ${exclude_scope} &
#        fi
#    else
#        if [ $multithread == y ]; then
#            split -n l/10 -d ${scope} ${asmtnum}-DISC
#            home=$(pwd)
#            mkdir -p ${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Scans
#            mkdir -p ${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Results
#            mv ${asmtnum}-DISC0* ${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Scans
#            cd ${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Scans
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC00 -p ${asmtnum}-DISC00 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC01 -p ${asmtnum}-DISC01 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC02 -p ${asmtnum}-DISC02 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC03 -p ${asmtnum}-DISC03 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC04 -p ${asmtnum}-DISC04 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC05 -p ${asmtnum}-DISC05 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC06 -p ${asmtnum}-DISC06 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC07 -p ${asmtnum}-DISC07 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC08 -p ${asmtnum}-DISC08 &
#            MESA-Toolkit -o discovery -i ${asmtnum}-DISC09 -p ${asmtnum}-DISC09 &
#            top
#            cp ${asmtnum}-DISC0*/Port_Scans/DISCOVERY/${asmtnum}* ${home}/${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Results/
#            cd ${home}/${asmtnum}-Multi_Threaded_Scans/DISCOVERY/Results/
#            parser=$(locate Gnmap-Parser.sh)
#            bash ${parser} -p
#        else
#            MESA-Toolkit -o discovery -i ${scope} -p ${asmtnum}
#        fi
#    fi
}

function full() {
    read -p "Have you ran discovery scans yet? (y or n): " -r disc_check
        if [ $disc_check == n ]; then
            echo "##########################################"
            echo "#                                        #"
            echo "# You must first run discovery scans!    #"
            echo "#                                        #"
            echo "##########################################"
            exit
        else
            read -p "Enter the assessment number: " -r asmtnum
            read -p "Enter path to live hosts file: " -i "" -e scope
            read -p "Are there any IPs that must be excluded? (y or n): " -r exclude
#            read -p "Would you like to run a multithreaded scan? (y or n): " -r multithread
            if [ $exclude == y ]; then
                read -p "Enter path to exclude scope file: " -i "" -e exclude_scope
                MESA-Toolkit -o full -i ${scope} -p ${asmtnum} -e ${exclude_scope}
            else
                MESA-Toolkit -o full -i ${scope} -p ${asmtnum}
            fi
        fi
# The following section is experimental and is not ready for production. Do not uncomment without understanding the potential ramifications.
#                if [ $multithread == y ]; then
#                    split -n l/10 -d ${scope} ${asmtnum}-FULL
#                    home=$(pwd)
#                    mkdir -p ${asmtnum}-Multi_Threaded_Scans/FULL/Scans
#                    mkdir -p ${asmtnum}-Multi_Threaded_Scans/FULL/Results
#                    mv ${asmtnum}-FULL0* ${asmtnum}-Multi_Threaded_Scans/FULL/Scans
#                    cd ${asmtnum}-Multi_Threaded_Scans/FULL/Scans
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL00 -p ${asmtnum}-FULL00 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL01 -p ${asmtnum}-FULL01 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL02 -p ${asmtnum}-FULL02 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL03 -p ${asmtnum}-FULL03 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL04 -p ${asmtnum}-FULL04 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL05 -p ${asmtnum}-FULL05 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL06 -p ${asmtnum}-FULL06 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL07 -p ${asmtnum}-FULL07 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL08 -p ${asmtnum}-FULL08 -e ${exclude_scope} &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL09 -p ${asmtnum}-FULL09 -e ${exclude_scope} &
#                    cp ${asmtnum}-FULL0*/Port_Scans/FULL/${asmtnum}* ${home}/${asmtnum}-Multi_Threaded_Scans/FULL/Results/
#                    cd ${home}/${asmtnum}-Multi_Threaded_Scans/FULL/Results/
#                    parser=$(locate Gnmap-Parser.sh)
#                    bash ${parser} -p
#                else
#                    MESA-Toolkit -o full -i ${scope} -p ${asmtnum} -e ${exclude_scope}
#                fi
#            else
#                if [ $multithread == y ]; then
#                    split -n l/10 -d ${scope} ${asmtnum}-FULL
#                    home=$(pwd)
#                    mkdir -p ${asmtnum}-Multi_Threaded_Scans/FULL/Scans
#                    mkdir -p ${asmtnum}-Multi_Threaded_Scans/FULL/Results
#                    mv ${asmtnum}-FULL0* ${asmtnum}-Multi_Threaded_Scans/FULL/Scans
#                    cd ${asmtnum}-Multi_Threaded_Scans/FULL/Scans
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL00 -p ${asmtnum}-FULL00 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL01 -p ${asmtnum}-FULL01 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL02 -p ${asmtnum}-FULL02 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL03 -p ${asmtnum}-FULL03 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL04 -p ${asmtnum}-FULL04 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL05 -p ${asmtnum}-FULL05 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL06 -p ${asmtnum}-FULL06 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL07 -p ${asmtnum}-FULL07 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL08 -p ${asmtnum}-FULL08 &
#                    MESA-Toolkit -o full -i ${asmtnum}-FULL09 -p ${asmtnum}-FULL09 &
#                    cp ${asmtnum}-FULL0*/Port_Scans/FULL/${asmtnum}* ${home}/${asmtnum}-Multi_Threaded_Scans/FULL/Results/
#                    cd ${home}/${asmtnum}-Multi_Threaded_Scans/FULL/Results/
#                    parser=$(locate Gnmap-Parser.sh)
#                    bash ${parser} -p
#                else
#                    MESA-Toolkit -o full -i ${scope} -p ${asmtnum}
#                fi
#            fi
#        fi
}

function aquatone() {
    read -p "Have you ran discovery scans yet? (y or n): " -r disc_check
        if [ $disc_check == n ]; then
            echo "##########################################"
            echo "#                                        #"
            echo "# You must first run discovery scans!    #"
            echo "#                                        #"
            echo "##########################################"
            exit
        else
            read -p "Enter the assessment number: " -r asmtnum
            read -p "Enter path to PeepingTom.txt file (Located in Parsed-Results folder of Discovery Scans): " -i "" -e scope
            MESA-Toolkit -o aquatone -i ${scope} -p ${asmtnum}
        fi
}

function vuln_scan() {
    read -p "Have you ran discovery scans yet? (y or n): " -r disc_check
        if [ $disc_check == n ]; then
            echo "##########################################"
            echo "#                                        #"
            echo "# You must first run discovery scans!    #"
            echo "#                                        #"
            echo "##########################################"
            exit
        else
            read -p "Enter the assessment number: " -r asmtnum
            read -p "Enter path to live hosts file: " -i "" -e scope
            MESA-Toolkit -o vuln_scans -i ${scope} -p ${asmtnum}
        fi
# The following section is experimental and is not ready for production. Do not uncomment without understanding the potential ramifications.
#        else
#            read -p "Enter the assessment number: " -r asmtnum
#            read -p "Enter path to live hosts file: " -i "" -e scope
#            read -p "Would you like to run a multithreaded scan? (y or n): " -r multithread
#            if [ $multithread == y ]; then
#               split -n l/10 -d ${scope} ${asmtnum}-VULN
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN00 -p ${asmtnum}-VULN00 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN01 -p ${asmtnum}-VULN01 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN02 -p ${asmtnum}-VULN02 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN03 -p ${asmtnum}-VULN03 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN04 -p ${asmtnum}-VULN04 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN05 -p ${asmtnum}-VULN05 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN06 -p ${asmtnum}-VULN06 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN07 -p ${asmtnum}-VULN07 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN08 -p ${asmtnum}-VULN08 &
#                MESA-Toolkit -o vuln_scans -i ${asmtnum}-VULN09 -p ${asmtnum}-VULN09 &
#                top
#                mkdir -p ${asmtnum}_Scans/Vulnerability_Scans/
#                cp ${asmtnum}-VULN0*_Scans/Vulnerability_Scans/* ${asmtnum}_Scans/Vulnerability_Scans/
#                rm -rf ${asmtnum}-VULN0*
#            else
#                MESA-Toolkit -o vuln_scans -i ${scope} -p ${asmtnum}
#            fi
#        fi
}

function encryption_check() {
    read -p "Enter the assessment number: " -r asmtnum
    read -p "Enter path to inscope file: " -i "" -e scope
    read -p "Are there any IPs that must be excluded? (y or n): " -r exclude
#    read -p "Would you like to run a multithreaded scan? (y or n): " -r multithread
    if [ $exclude == y ]; then
        read -p "Enter path to exclude scope file: " -i "" -e exclude_scope
        MESA-Toolkit -o encryption_check -i ${scope} -p ${asmtnum} -e ${exclude_scope}
    else
        MESA-Toolkit -o encryption_check -i ${scope} -p ${asmtnum}
    fi
# The following section is experimental and is not ready for production. Do not uncomment without understanding the potential ramifications.
#        if [ $multithread == y ]; then
#            split -n l/10 -d ${scope} ${asmtnum}-EC
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC00 -p ${asmtnum}-EC00 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC01 -p ${asmtnum}-EC01 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC02 -p ${asmtnum}-EC02 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC03 -p ${asmtnum}-EC03 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC04 -p ${asmtnum}-EC04 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC05 -p ${asmtnum}-EC05 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC06 -p ${asmtnum}-EC06 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC07 -p ${asmtnum}-EC07 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC08 -p ${asmtnum}-EC08 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC09 -p ${asmtnum}-EC09 -e ${exclude_scope}
#        else
#            MESA-Toolkit -o encryption_check -i ${scope} -p ${asmtnum} -e ${exclude_scope}
#        fi
#    else
#        if [ $multithread == y ]; then
#            split -n l/10 -d ${scope} ${asmtnum}-EC
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC00 -p ${asmtnum}-EC00 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC01 -p ${asmtnum}-EC01 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC02 -p ${asmtnum}-EC02 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC03 -p ${asmtnum}-EC03 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC04 -p ${asmtnum}-EC04 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC05 -p ${asmtnum}-EC05 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC06 -p ${asmtnum}-EC06 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC07 -p ${asmtnum}-EC07 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC08 -p ${asmtnum}-EC08 -e ${exclude_scope}
#            MESA-Toolkit -o encryption_check -i ${asmtnum}-EC09 -p ${asmtnum}-EC09 -e ${exclude_scope}
#        else
#            MESA-Toolkit -o encryption_check -i ${scope} -p ${asmtnum}
#        fi
#    fi
}

function default_logins() {
    read -p "Enter the assessment number: " -r asmtnum
    read -p "Enter path to inscope file: " -i "" -e scope
    read -p "Are there any IPs that must be excluded? (y or n): " -r exclude
#    read -p "Would you like to run a multithreaded scan? (y or n): " -r multithread
    if [ $exclude == y ]; then
        read -p "Enter path to exclude scope file: " -i "" -e exclude_scope
        MESA-Toolkit -o default_logins -i ${scope} -p ${asmtnum} -e ${exclude_scope}
    else
        MESA-Toolkit -o default_logins -i ${scope} -p ${asmtnum}
    fi
# The following section is experimental and is not ready for production. Do not uncomment without understanding the potential ramifications.
#        if [ $multithread == y ]; then
#            split -n l/10 -d ${scope} ${asmtnum}-DL
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL00 -p ${asmtnum}-DL00 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL01 -p ${asmtnum}-DL01 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL02 -p ${asmtnum}-DL02 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL03 -p ${asmtnum}-DL03 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL04 -p ${asmtnum}-DL04 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL05 -p ${asmtnum}-DL05 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL06 -p ${asmtnum}-DL06 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL07 -p ${asmtnum}-DL07 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL08 -p ${asmtnum}-DL08 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL09 -p ${asmtnum}-DL09 -e ${exclude_scope}
#        else
#            MESA-Toolkit -o default_logins -i ${scope} -p ${asmtnum} -e ${exclude_scope}
#        fi
#    else
#        if [ $multithread == y ]; then
#            split -n l/10 -d ${scope} ${asmtnum}-DL
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL00 -p ${asmtnum}-DL00 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL01 -p ${asmtnum}-DL01 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL02 -p ${asmtnum}-DL02 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL03 -p ${asmtnum}-DL03 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL04 -p ${asmtnum}-DL04 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL05 -p ${asmtnum}-DL05 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL06 -p ${asmtnum}-DL06 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL07 -p ${asmtnum}-DL07 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL08 -p ${asmtnum}-DL08 -e ${exclude_scope}
#            MESA-Toolkit -o default_logins -i ${asmtnum}-DL09 -p ${asmtnum}-DL09 -e ${exclude_scope}
#        else
#            MESA-Toolkit -o default_logins -i ${scope} -p ${asmtnum}
#        fi
#    fi
}

function smb_signing_check() {
    read -p "Have you ran discovery scans yet? (y or n): " -r disc_check
        if [ $disc_check == n ]; then
            echo "##########################################"
            echo "#                                        #"
            echo "# You must first run discovery scans!    #"
            echo "#                                        #"
            echo "##########################################"
            exit
        else
            read -p "Enter the assessment number: " -r asmtnum
            read -p "Enter path to 445-TCP.txt file: " -i "" -e scope
            MESA-Toolkit -o smb_signing_check -i ${scope} -p ${asmtnum}
        fi
}

function pass_policy_check() {
    read -p "Have you been provided with a domain user account from the PoC? (y or n): " -r cred_check
        if [ $cred_check == n ]; then
            echo "#################################################"
            echo "#                                               #"
            echo "# Request domain user credentials from PoC!     #"
            echo "#                                               #"
            echo "#################################################"
            exit
        else
            read -p "Enter the assessment number: " -r asmtnum
            read -p "Enter path to scope file: " -i "" -e scope
            read -p "Enter provided domain username: " -r username
            read -p "Enter provided password for domain user: " -r password
            read -p "Enter domain controller IP address: " -r dc
            read -p "Enter domain name: " -r domain
            MESA-Toolkit -o pass_policy_check -i ${scope} -p ${asmtnum} -d ${domain} -dc ${dc} -du ${username} -dp ${password}
        fi
}

function domain_enum() {
    echo "###########################################################"
    echo "#                                                         #"
    echo "# Be sure the neo4j service is running before continuing! #"
    echo "#                                                         #"
    echo "###########################################################"

    read -p "Have you been provided with a domain user account from the PoC? (y or n): " -r cred_check
        if [ $cred_check == n ]; then
            echo "#################################################"
            echo "#                                               #"
            echo "# Request domain user credentials from PoC!     #"
            echo "#                                               #"
            echo "#################################################"
            exit
        else
            read -p "Enter the assessment number: " -r asmtnum
            read -p "Enter path to scope file: " -i "" -e scope
            read -p "Enter provided domain username: " -r username
            read -p "Enter provided password for domain user: " -r password
            read -p "Enter domain controller IP address: " -r dc
            read -p "Enter domain name: " -r domain
            read -p "Enter neo4j username: " -r nu
            read -p "Enter neo4j password: " -r np
            MESA-Toolkit -o domain_enum -i ${scope} -p ${asmtnum} -d ${domain} -dc ${dc} -du ${username} -dp ${password} -nu ${nu} -np ${np}
        fi
}

function all_checks() {
    echo "###########################################################"
    echo "#                                                         #"
    echo "# Be sure the neo4j service is running before continuing! #"
    echo "#                                                         #"
    echo "###########################################################"

    read -p "Have you been provided with a domain user account from the PoC? (y or n): " -r cred_check
        if [ $cred_check == n ]; then
            echo "#################################################"
            echo "#                                               #"
            echo "# Request domain user credentials from PoC!     #"
            echo "#                                               #"
            echo "#################################################"
            exit
        else
            read -p "Are there any IPs that must be excluded? (y or n): " -r exclude
            if [ $exclude == y ]; then
                read -p "Enter path to exclude scope file: " -i "" -e exclude_scope
                read -p "Enter the assessment number: " -r asmtnum
                read -p "Enter path to scope file: " -i "" -e scope
                read -p "Enter provided domain username: " -r username
                read -p "Enter provided password for domain user: " -r password
                read -p "Enter domain controller IP address: " -r dc
                read -p "Enter domain name: " -r domain
                read -p "Enter neo4j username: " -r nu
                read -p "Enter neo4j password: " -r np
                MESA-Toolkit -o all_checks -i ${scope} -e ${exclude_scope} -p ${asmtnum} -d ${domain} -dc ${dc} -du ${username} -dp ${password} -nu ${nu} -np ${np}
            else
                read -p "Enter the assessment number: " -r asmtnum
                read -p "Enter path to scope file: " -i "" -e scope
                read -p "Enter provided domain username: " -r username
                read -p "Enter provided password for domain user: " -r password
                read -p "Enter domain controller IP address: " -r dc
                read -p "Enter domain name: " -r domain
                read -p "Enter neo4j username: " -r nu
                read -p "Enter neo4j password: " -r np
                MESA-Toolkit -o all_checks -i ${scope} -p ${asmtnum} -d ${domain} -dc ${dc} -du ${username} -dp ${password} -nu ${nu} -np ${np}
            fi
        fi
}

PS3="MESA Assistant - Pick an option: "
options=("Scope File Creator" "Discovery Scans" "Full Port Scans" "Web Application Enumeration" "Vulnerability Scans" "Encryption Check" "Default Login Check" "SMB Signing Check" "Password Policy Check" "Domain Enumeration" "All Scans")
select opt in "${options[@]}" "Quit"; do

    case "$REPLY" in
            
    1) scoper;;

    2) discovery;;

    3) full;;

    4) aquatone;;
    
    5) vuln_scan;;

    6) encryption_check;;

    7) default_logins;;

    8) smb_signing_check;;

    9) pass_policy_check;;

    10) domain_enum;;

    11) all_checks;;

    $(( ${#options[@]}+1 )) ) echo "Thank you for using the MESA-Assistant! Have a great day!"; break;;
    *) echo "Invalid option. Try another one.";continue;;

    esac
done