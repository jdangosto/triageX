#!/bin/bash
clear
server_name=$(hostname -s)
day=$(date +"%m-%d-%Y-%T")
basedir="triageX.$server_name.$day"
mkdir triageX.$server_name.$day

echo $server_name
echo $basedir

function check_root() {
    echo ""
        echo "Checking for root/sudo priviliges: "
    if whoami | grep "root"; then
     echo "Congratulations! You have root/sudo privileges..." 
else
     echo "!!! YOU ARE NOT ROOT !!!  PLEASE RE-RUN THIS SCRIPT WITH ROOT PRIVILIGES!" && exit
fi
    echo ""
}
function banner(){
echo -ne "
##################################################### 
#                      TRIAGEX                      #
#                   --------------                  #	
#            Triage Tool for *NIX System            #
#                    BETA Version                   #
#---------------------------------------------------#
#           Author: Jesus D. Angosto                #
#                    @jdangosto                     #
##################################################### 
" | tee -a $basedir/triageX.txt
sleep 5
}

function FIN(){
echo -ne "
##################################################### 
#                      TRIAGEX                      #
#                   --------------                  #	
#            Triage Tool for *NIX System            #
#                   BETA Version                    #
#---------------------------------------------------#
#                   ALL TASK DONE!!!                #
#             GOOD LUCK IN YOUR RESEARCH            #
##################################################### 
" | tee -a $basedir/triageX.txt
}

function systemInformation(){
echo -e "[ COLLECTING SYSTEM INFORMATION... ] " | tee -a $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ HOST NAME ]" >> $basedir/system_info.txt
echo -e "-------------" >> $basedir/system_info.txt
hostnamectl >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ LINUX VERSION AND KERNEL ]" >> $basedir/system_info.txt
echo -e "----------------------------" >> $basedir/system_info.txt
uname -a >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ SYSTEM DATE / TIME / TIMEZONE ]" >> $basedir/system_info.txt
echo -e "--------------------------------- " >> $basedir/system_info.txt
timedatectl >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ UPTIME ]" >> $basedir/system_info.txt
echo -e "----------" >> $basedir/system_info.txt
uptime >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ MEMORY INFORMATION ]" >> $basedir/system_info.txt
echo -e "----------------------" >> $basedir/system_info.txt
free >> $basedir/system_info.txt
echo -e "**************************************************************************************" >> $basedir/system_info.txt
cat /proc/meminfo >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ LAST INFORMATION ]" >> $basedir/system_info.txt
echo -e "-------------------- " >> $basedir/system_info.txt
last reboot >> $basedir/system_info.txt
echo -e "**************************************************************************************" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ LASTB INFO: FAILED ATTEMPTS ]" >> $basedir/system_info.txt
echo -e "------------------------------- " >> $basedir/system_info.txt
lastb >> $basedir/system_info.txt
echo -e "**************************************************************************************" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ FILES WITH SPECIFIC ACLS ]" >> $basedir/system_info.txt
echo -e "---------------------------- " >> $basedir/system_info.txt
getfacl -R -s -p /raiz >> $basedir/system_info.txt
echo -e "***************************************************************************************" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ USERS LAST LOGIN ]" >> $basedir/system_info.txt
echo -e "-------------------- " >> $basedir/system_info.txt
lastlog >> $basedir/system_info.txt
echo -e "***************************************************************************************" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[LAST INFO]" >> $basedir/system_info.txt
echo -e "----------- " >> $basedir/system_info.txt
last -xFa >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ LAST SYSTEM BOOT TIME ]" >> $basedir/system_info.txt
echo -e "------------------------- " >> $basedir/system_info.txt
who -b >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ USERS CURRENTLY LOGGED ON ]" >> $basedir/system_info.txt
echo -e "----------------------------- "
who -H >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ ACCOUNTS ]" >> $basedir/system_info.txt
echo -e "------------ " >> $basedir/system_info.txt
cat /etc/passwd >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ GROUPS] " >> $basedir/system_info.txt
echo -e "--------- " >> $basedir/system_info.txt
cat /etc/group >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ SUDOERS ]" >> $basedir/system_info.txt
echo -e "----------- " >> $basedir/system_info.txt
cat /etc/sudoers >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ CRONTAB ] - Schedule jobs" >> $basedir/system_info.txt
echo -e "--------------------------- " >> $basedir/system_info.txt
cat /etc/crontab >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ SYSTEMD TIMERS ]" >> $basedir/system_info.txt
echo -e "------------------ " >> $basedir/system_info.txt
systemctl status *timer >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ ALL ] scheduled jobs" >> $basedir/system_info.txt
echo -e "----------------------- " >> $basedir/system_info.txt
cat /etc/*.d >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ CPU's ]" >> $basedir/system_info.txt
echo -e "--------- " >> $basedir/system_info.txt
lscpu >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ BLOCK DEVICES ]" >> $basedir/system_info.txt
echo -e "----------------- " >> $basedir/system_info.txt
lsblk -a >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ USB DEVICES ]" >> $basedir/system_info.txt
echo -e "--------------- " >> $basedir/system_info.txt
lsusb -v >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ PCI DEVICES ]" >> $basedir/system_info.txt
echo -e "--------------- " >> $basedir/system_info.txt
lspci -v >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ SCSI DEVICES ]" >> $basedir/system_info.txt
echo -e "---------------- " >> $basedir/system_info.txt
lsscsi -s >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ HARD DRIVES ]" >> $basedir/system_info.txt
echo -e "--------------- " >> $basedir/system_info.txt
fdisk -l >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ MOUNTABLE PARTITIONS ]" >> $basedir/system_info.txt
echo -e "------------------------ " >> $basedir/system_info.txt
blkid >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ MOUNTED FILE SYSTEMS AND DISK SPACE ]" >> $basedir/system_info.txt
echo -e "--------------------------------------- " >> $basedir/system_info.txt
df -h >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo -e " " >> $basedir/system_info.txt
echo -e "[ ALL MOUNT POINTS ]" >> $basedir/system_info.txt
echo -e "-------------------- " >> $basedir/system_info.txt
cat /proc/mounts >> $basedir/system_info.txt
echo -e "======================================================================================" >> $basedir/system_info.txt
echo "COLLECTING SYSTEM INFORMATION... DONE!" | tee -a $basedir/system_info.txt
echo "**************************************************************************************" >> $basedir/system_info.txt
}

function getProcess(){
    echo "**************************************************************************************" >> $basedir/process.txt
    echo "COLLECTING LIST OF PROCESSES..." >> $basedir/process.txt
    echo "======================================================================================" >> $basedir/process.txt
    echo -e " " >> $basedir/process.txt
    echo -e "[ RUNNING PROCESS WITH PID ]" >> $basedir/process.txt
    echo -e "--------------------------" >> $basedir/process.txt
    pstree -p -n >> $basedir/process.txt
    echo -e "======================================================================================" >> $basedir/process.txt
    echo -e >> $basedir/process.txt
    echo -e "[ PROCESS TREE FORMAT ]" >> $basedir/process.txt
    echo -e "-------------------------------" >> $basedir/process.txt
    pstree -a >> $basedir/process.txt
    echo -e "======================================================================================" >> $basedir/process.txt
    echo -e >> $basedir/process.txt
    echo -e "[ RUNNING PROCESSES ] " >> $basedir/process.txt
    echo -e "------------------" >> $basedir/process.txt
    ps -axu | tee -a $basedir/process.txt
    echo -e "======================================================================================" >> $basedir/process.txt
    echo -e >> $basedir/process.txt
    echo -e " [ RUNNING FROM /tmp or /dev DIRECTORY ]" >> $basedir/process.txt
    echo -e "------------------------------------" >> $basedir/process.txt
    ls -alR /proc/*/cwd 2> /dev/null | grep -E "tmp|dev" >> $basedir/process.txt
    echo -e "======================================================================================" >> $basedir/process.txt
    echo -e >> $basedir/process.txt
    echo -e "[ DELECTED BINARIES STILL RUNNING ]"
    echo -e "------------------------------" >> $basedir/process.txt
    ls -alR /proc/*/exe 2> /dev/null | grep deleted >> $basedir/process.txt
    echo -e "======================================================================================" >> $basedir/process.txt
    echo -e >> $basedir/process.txt
    echo -e "STARTUP SERVICES AT BOOT ]" >> $basedir/process.txt
    echo -e "--------------------------" >> $basedir/process.txt
    systemctl list-unit-files --type=service >> $basedir/process.txt
    echo -e "======================================================================================" >> $basedir/process.txt
    echo -e >> $basedir/process.txt
    echo -e "[ SERVICES AND THEIR STATUS ]" >> $basedir/process.txt
    echo -e "---------------------------------" >> $basedir/process.txt
    echo -e " [ ALL Services ]" >> $basedir/process.txt
    echo -e "--------------------------" >> $basedir/process.txt
    service --status-all >> $basedir/process.txt
    echo -e "======================================================================================" >> $basedir/process.txt
    echo -e "[ OPEN FILES ON THE SYSTEM AND THE PROCESS ID that opened them" >> $basedir/process.txt
    echo -e "------------------------------------------------------------" >> $basedir/process.txt
    lsof >> $basedir/process.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo "COLLECTING LIST OF PROCESSES... DONE!" >> $basedir/triageX.txt
    echo "**************************************************************************************" >> $basedir/process.txt
}

function getNetwork(){
    echo "COLLECTING NETWORK INFORMATION..." | tee -a $basedir/network_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo -e >> $basedir/process.txt
    echo -e "[ NETWORK DEVICES ]" >> $basedir/network_info.txt
    ip -a >> $basedir/network_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo -e "[ UFW ('uncomplicated firewall') ]" >> $basedir/firewall_info.txt
    echo -e "ufw status verbose" >> $basedir/firewall_info.txt
    ufw status verbose >> $basedir/firewall_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo -e >> $basedir/firewall_info.txt
    echo -e "[ IPTABLES ]" >> $basedir/firewall_info.txt
    iptables -L | tee -a $basedir/firewall_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo -e >> $basedir/firewall_info.txt
    echo "[ IPTABLES -nL] " >> firewall_info.txt
    iptables -nL >> $basedir/firewall_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo -e >> $basedir/firewall_info.txt
    echo -e "[ IPTABLES -nL -t nat] " >> firewall_info.txt
    iptables -nL -t nat >> $basedir/firewall_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo -e >> $basedir/firewall_info.txt
    echo "[ IPTABLES -nL -t mangle] " >> $basedir/iptables_info.txt
    iptables -nL -t mangle >> $basedir/iptables_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo -e >> $basedir/network_info.txt
    echo -e "[ NETWORK CONNECTIONS ]" >> $basedir/network_info.txt
    netstat -a >> $basedir/network_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
     echo -e >> $basedir/network_info.txt
    echo -e "[ NETWORK INTERFACES ]" >> $basedir/network_info.txt
    netstat -i >> $basedir/network_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
     echo -e >> $basedir/network_info.txt
    echo -e "[NETWORK ROUTING TABLE ]" >> $basedir/network_info.txt
    netstat -r >> $basedir/network_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
     echo -e >> $basedir/network_info.txt
    echo -e "[ NETWORK CONNECTIONS ]" >> $basedir/network_info.txt
    netstat -plant >> $basedir/network_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo -e >> $basedir/network_info.txt
    echo -e "[ ARP table ] ">> $basedir/network_info.txt
    arp -a >> $basedir/network_info.txt
    echo -e "======================================================================================" >> $basedir/network_info.txt
    echo "COLLECTING NETWORK INFORMATION... DONE!" | tee -a $basedir/triageX.txt
}

function getDirectoryAndFiles(){
    
    echo "CREATING DIRECTORY LISTING OF FILES..." | tee -a $basedir/triageX.txt
    echo -e "======================================================================================" >> $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "[ FULL DIRECTORY LISTING ] " >> $basedir/directory_and_files.txt
    ls -l -A -h -R / | tee -a  $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "======================================================================================" >> $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e " [ ALL HIDDEN DIRECTORIES ]" >> $basedir/directory_and_files.txt
    find / -type d -name "\.*" >> $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "======================================================================================" >> $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "Files/directories with no user/group name:" >> $basedir/directory_and_files.txt
    find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null >> $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "======================================================================================" >> $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "MD5 hash for all executable files" >> $basedir/directory_and_files.txt
    find /usr/bin -type f -exec file "{}" \; | grep -i "elf" | cut -f1 -d: | xargs -I "{}" -n 1 md5sum {} >> $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "======================================================================================" >> $basedir/directory_and_files.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "ALL log files that contain binary code inside" >> $basedir/directory_and_files.txt
    grep [[:cntrl:]] /var/log/*.txt >> $basedir/system_info.txt
    echo -e " " >> $basedir/directory_and_files.txt
    echo -e "======================================================================================" >> $basedir/directory_and_files.txt
    echo "CREATING DIRECTORY LISTING OF FILES... DONE!" | tee -a $basedir/system_info.txt
}

function copyFolder(){
    echo "COPY AND COMPRESSING FOLDERS..." | tee -a $basedir/triageX.txt
    tar --exclude=$basedir -cvzf home.tar.gz /home
    tar -cvzf root.tar.gz /root 
    tar -cvzf logs.tar.gz /var/log
    mv *.gz $basedir
    echo "COPY AND COMPRESSING FOLDERS... DONE!" | tee -a $basedir/triageX.txt
}

function getHashes(){
    echo "GETTING HASHES....." 
    echo -e "======================================================================================" >> $basedir/hashes.txt
    echo -e "COMPUTING MD5" >> $basedir/hashes.txt
    echo -e "======================================================================================" >> $basedir/hashes.txt
    echo "md5sum=$(md5sum $basedir/*.mem)" | tee -a $basedir/hashes.txt
    echo "md5sum=$(md5sum $basedir/*.txt)" | tee -a $basedir/hashes.txt
    echo "md5sum=$(md5sum $basedir/*.gz)" | tee -a $basedir/hashes.txt
    echo -e "======================================================================================" >> $basedir/hashes.txt
    echo -e "COMPUTING SHA1" >> $basedir/hashes.txt
    echo -e "======================================================================================" >> $basedir/hashes.txt
    echo "sha1sum=$(sha1sum $basedir/*.mem)" | tee -a $basedir/hashes.txt
    echo "sha1sum=$(sha1sum $basedir/*.txt)" | tee -a $basedir/hashes.txt
    echo "sha1sum=$(sha1sum $basedir/*.gz)" | tee -a $basedir/hashes.txt
    echo -e "======================================================================================" >> $basedir/hashes.txt
    echo -e "COMPUTING SHA256" >> $basedir/hashes.txt
    echo -e "======================================================================================" >> $basedir/hashes.txt
    echo "sha256sum=$(sha256sum $basedir/*.mem)" | tee -a $basedir/hashes.txt
    echo "sha256sum=$(sha256sum $basedir/*.txt)" | tee -a $basedir/hashes.txt
    echo "sha256sum=$(sha256sum $basedir/*.gz)" | tee -a $basedir/hashes.txt
}

function getPackages(){
    echo "GETTING PACKAGES....." | tee -a $basedir/triageX.txt
    if command -v dpkg &> /dev/null; then
    dpkg --version > /dev/null 2>/dev/null
        echo -e "[dpkg -l] No chroot!!" >> $basedir/packages_info.txt
        dpkg -l >> $basedir/packages_info.txt
        echo -e "======================================================================================" >> $basedir/packages_info.txt
        echo "[ls -tl /var/lib/dpkg/info/] No chroot!!" >> $basedir/packages_info.txt
        ls -tl /var/lib/dpkg/info/ >> $basedir/packages_info.txt
        echo -e "======================================================================================" >> $basedir/packages_info.txt
        echo "apt-key list" >> $basedir/gpg_file.txt
        apt-key list >> $basedir/gpg_file.txt
        echo -e "======================================================================================" >> $basedir/packages_info.txt
    elif command -v rpm &> /dev/null; then
       rpm --version >> packages_info.txt
       echo -e "[ RPM -qa --last] No chroot!!" >> packages_info.txt
       rpm -qa --last >> packages_info.txt
       rpm -Va >> packages_info.txt
       echo "[rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}] No chroot!!'" >> packages_info.txt
       rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n' >> packages_info.txt
       rpm -qa >> packages_info.txt
    else
            echo "Tipo de paquete desconocido o no soportado" >> $basedir/packages_info.txt
    fi
    echo "GETTING PACKAGES.....DONE!!!" | tee -a $basedir/triageX.txt
}

function main(){
    check_root
    banner
    echo "**************************************************************************************" | tee -a $basedir/triageX.txt
    echo "Create triage collection from:" $server_name | tee -a $basedir/triageX.txt
    echo "Date:" $day | tee -a $basedir/triageX.txt
    echo " "
    #Collect Linux Memory Image using Microsoft's AVML tool.
    echo "COLLECTING MEMORY IMAGE WITH MICROSOFT'S AVML...PLEASE WAIT" | tee -a $basedir/triageX.txt
    ./avml $basedir/memory.mem
    sleep 2
    echo "COLLECTING MEMORY IMAGEN...DONE!!!" | tee -a $basedir/triageX.txt
    sleep 2
    echo "COLLECTING FILE TIMELINE...timeline.txt....PLEASE WAIT" | tee -a $basedir/triageX.txt
    sleep 2
    echo -e "Access date;Access time;Modify date;Modify time;Create date;Create time;Permissions;UID;Username;GID;Groupname;Size;File" >> $basedir/timeline_file.txt
    find / -printf "%Ax;%AT;%Tx;%TT;%Cx;%CT;%m;%U;%u;%G;%g;%s;%p\n" 2>/dev/null  >> $basedir/timeline_file.txt
    echo "COLLECTING FILE TIMELINE >> timeline.txt....DONE!!!" | tee -a $basedir/triageX.txt
    sleep 2
    echo "COLLECTING SYSTEM INFORMATION >> system_info.txt" | tee -a $basedir/triageX.txt
    systemInformation
    echo "COLLECTING SYSTEM INFORMATION ..... DONE!!!" | tee -a $basedir/triageX.txt
    sleep 2
    getProcess
    sleep 2
    echo "GETTING TOP...[top 2 times] ...." | tee -a $basedir/triageX.txt
    top -b -n 2 >> $basedir/top_file.txt
    echo "GETTING TOP...[top 2 times] ..... DONE" | tee -a $basedir/triageX.txt
    sleep 2
    getNetwork
    sleep 2
    getDirectoryAndFiles
    sleep 2
    copyFolder
    sleep 2
    getPackages
    sleep 2
    getHashes
    sleep 2
    FIN
}

main
