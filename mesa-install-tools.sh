#! /bin/bash

#obligatory ascii art...
func_vm_tools(){
RED='\033[0;31m'
echo -e "${RED}
                                                                                                                                                                                              
MMMMMMMM               MMMMMMMMEEEEEEEEEEEEEEEEEEEEEE   SSSSSSSSSSSSSSS              AAA               
M:::::::M             M:::::::ME::::::::::::::::::::E SS:::::::::::::::S            A:::A              
M::::::::M           M::::::::ME::::::::::::::::::::ES:::::SSSSSS::::::S           A:::::A             
M:::::::::M         M:::::::::MEE::::::EEEEEEEEE::::ES:::::S     SSSSSSS          A:::::::A            
M::::::::::M       M::::::::::M  E:::::E       EEEEEES:::::S                     A:::::::::A           
M:::::::::::M     M:::::::::::M  E:::::E             S:::::S                    A:::::A:::::A          
M:::::::M::::M   M::::M:::::::M  E::::::EEEEEEEEEE    S::::SSSS                A:::::A A:::::A         
M::::::M M::::M M::::M M::::::M  E:::::::::::::::E     SS::::::SSSSS          A:::::A   A:::::A        
M::::::M  M::::M::::M  M::::::M  E:::::::::::::::E       SSS::::::::SS       A:::::A     A:::::A       
M::::::M   M:::::::M   M::::::M  E::::::EEEEEEEEEE          SSSSSS::::S     A:::::AAAAAAAAA:::::A      
M::::::M    M:::::M    M::::::M  E:::::E                         S:::::S   A:::::::::::::::::::::A     
M::::::M     MMMMM     M::::::M  E:::::E       EEEEEE            S:::::S  A:::::AAAAAAAAAAAAA:::::A    
M::::::M               M::::::MEE::::::EEEEEEEE:::::ESSSSSSS     S:::::S A:::::A             A:::::A   
M::::::M               M::::::ME::::::::::::::::::::ES::::::SSSSSS:::::SA:::::A               A:::::A  
M::::::M               M::::::ME::::::::::::::::::::ES:::::::::::::::SSA:::::A                 A:::::A 
MMMMMMMM               MMMMMMMMEEEEEEEEEEEEEEEEEEEEEE SSSSSSSSSSSSSSS AAAAAAA                   AAAAAAA
                                                                                                       
"
echo ""

start=$(pwd)
cd /opt/
home=$(pwd)

# Install tools with apt
apt update
apt install ufw -y
apt install neo4j -y
apt install python3.11-venv -y
apt install chromium -y
apt install jq -y
apt install golang-go -y

# Start neo4j service
cd /usr/share/neo4j/bin/
set +o history
./neo4j-admin set-initial-password BloodHound
neo4j start &
cd $home
update-alternatives --set java $(update-alternatives --list java | grep java-11)

# Install nuclei and update templates
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
cp /root/go/bin/nuclei /usr/bin/
nuclei -ut

# Install aquatone
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip -o aquatone_linux_amd64_1.7.0.zip
mv aquatone /usr/bin/
rm aquatone_linux_amd64_1.7.0.zip LICENSE.txt README.md

# Clone git repositories
git clone https://github.com/fox-it/BloodHound.py.git
git clone --branch initial https://github.com/coffeegist/bloodhunt.git
git clone https://github.com/m1j09830/gnmap-parser.git

# Install MESA-Toolkit dependencies
python3 -m venv MESA-venv
source MESA-venv/bin/activate
cd BloodHound.py/
pip install .
cd $home
cd bloodhunt/
pip install .
cd $home
pip install --upgrade knowsmore
cd $start
pip install .

echo "########################################################################################"
echo "# All dependencies have been installed in a virtual enviroment located in /opt.        #"
echo "# Activate the virtual environment by running source /opt/MESA-venv/bin/activate.      #"
echo "# Once activated the MESA-Toolkit help menu can be shown by running MESA-Toolkit -h    #"
echo "########################################################################################"

}


func_pi_tools(){
RED='\033[0;31m'
echo -e "${RED}
                                                                                                                                                                                              
MMMMMMMM               MMMMMMMMEEEEEEEEEEEEEEEEEEEEEE   SSSSSSSSSSSSSSS              AAA               
M:::::::M             M:::::::ME::::::::::::::::::::E SS:::::::::::::::S            A:::A              
M::::::::M           M::::::::ME::::::::::::::::::::ES:::::SSSSSS::::::S           A:::::A             
M:::::::::M         M:::::::::MEE::::::EEEEEEEEE::::ES:::::S     SSSSSSS          A:::::::A            
M::::::::::M       M::::::::::M  E:::::E       EEEEEES:::::S                     A:::::::::A           
M:::::::::::M     M:::::::::::M  E:::::E             S:::::S                    A:::::A:::::A          
M:::::::M::::M   M::::M:::::::M  E::::::EEEEEEEEEE    S::::SSSS                A:::::A A:::::A         
M::::::M M::::M M::::M M::::::M  E:::::::::::::::E     SS::::::SSSSS          A:::::A   A:::::A        
M::::::M  M::::M::::M  M::::::M  E:::::::::::::::E       SSS::::::::SS       A:::::A     A:::::A       
M::::::M   M:::::::M   M::::::M  E::::::EEEEEEEEEE          SSSSSS::::S     A:::::AAAAAAAAA:::::A      
M::::::M    M:::::M    M::::::M  E:::::E                         S:::::S   A:::::::::::::::::::::A     
M::::::M     MMMMM     M::::::M  E:::::E       EEEEEE            S:::::S  A:::::AAAAAAAAAAAAA:::::A    
M::::::M               M::::::MEE::::::EEEEEEEE:::::ESSSSSSS     S:::::S A:::::A             A:::::A   
M::::::M               M::::::ME::::::::::::::::::::ES::::::SSSSSS:::::SA:::::A               A:::::A  
M::::::M               M::::::ME::::::::::::::::::::ES:::::::::::::::SSA:::::A                 A:::::A 
MMMMMMMM               MMMMMMMMEEEEEEEEEEEEEEEEEEEEEE SSSSSSSSSSSSSSS AAAAAAA                   AAAAAAA
                                                                                                       
"
echo ""

start=$(pwd)
cd /opt/
home=$(pwd)

# Install tools with apt
apt update
apt install ufw -y
apt install neo4j -y
apt install python3.11-venv -y
apt install chromium -y
apt install jq -y
apt install golang-go -y

# Start neo4j service
cd /usr/share/neo4j/bin/
set +o history
./neo4j-admin set-initial-password BloodHound
neo4j start &
cd $home
update-alternatives --set java $(update-alternatives --list java | grep java-11)

# Install nuclei and update templates
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
cp /root/go/bin/nuclei /usr/bin/
nuclei -ut

# Install aquatone
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_arm64_1.7.0.zip
unzip -o aquatone_linux_arm64_1.7.0.zip
mv aquatone /usr/bin/
rm aquatone_linux_arm64_1.7.0.zip LICENSE.txt README.md

# Clone git repositories
git clone https://github.com/fox-it/BloodHound.py.git
git clone --branch initial https://github.com/coffeegist/bloodhunt.git
git clone https://github.com/m1j09830/gnmap-parser.git

# Install MESA-Toolkit dependencies
python3 -m venv MESA-venv
source MESA-venv/bin/activate
cd BloodHound.py/
pip install .
cd $home
cd bloodhunt/
pip install .
cd $home
pip install --upgrade knowsmore
cd $start
pip install .

echo "########################################################################################"
echo "# All dependencies have been installed in a virtual enviroment located in /opt.        #"
echo "# Activate the virtual environment by running source /opt/MESA-venv/bin/activate.      #"
echo "# Once activated the MESA-Toolkit help menu can be shown by running MESA-Toolkit -h    #"
echo "########################################################################################"

}

case ${1} in
  -vm)
    func_vm_tools ${2}
    ;;
  -pi)
    func_pi_tools ${2}
    ;;
  *)
    echo " Usage...: ${0} [OPTION]"
    echo ' Options.:'
    echo '           -vm = Install tools on Virtual Machine'
    echo '           -pi = Install tools on Pi'
    echo '           -h  = Show This Help'
esac