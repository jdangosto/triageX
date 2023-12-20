#!/bin/bash
clear
server_name=$(hostname)
mkdir = triageX_$hostname_$day
basedir="triageX/"
day=$(date +"%m-%d-%Y")


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
#       Linux TimeLine & Forensic Triage Tool       #
#                 BETA Version 0.1                  #
#---------------------------------------------------#
#           Author: Jesus D. Angosto                #
#                    @jdangosto                     #
#                   GNU GPL v 3.0                   #
##################################################### 
" | tee -a $basedir/triageX.log
}
function getHashes(){
   echo "**************************************************************************************" | tee -a $basedir/hashes.log
   echo "MD5 Hashes" | tee -a $basedir/hashes.log
   echo "**************************************************************************************" | tee -a $basedir/hashes.log
   echo "SHA1 Hashes" | tee -a $basedir/hashes.log
   echo "**************************************************************************************" | tee -a $basedir/hashes.log
   echo "SHA256 hashes" | tee -a $basedir/triageX.log
}

function systemInformation(){
echo "COLLECTING SYSTEM INFORMATION..." | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List the host name of machine:" >> $basedir/system_info.log
hostnamectl | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "Linux version and kernel information:" >> $basedir/system_info.log
uname -a | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of system date/time/timezone:" >> $basedir/system_info.log
timedatectl | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List uptime of machine:" >> $basedir/system_info.log
uptime | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of system memory information:" >> $basedir/system_info.log
free | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of system memory information:" >> $basedir/system_info.log
cat /proc/meminfo | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List last reboot time of machine:" >> $basedir/system_info.log
last reboot | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of users currently logged on:" >> $basedir/system_info.log
who -H | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List last system boot time:" >> $basedir/system_info.log
who -b | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of ALL accounts on the machine:" >> $basedir/system_info.log
cat /etc/passwd | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of ALL groups used by the user:" >> $basedir/system_info.log
cat /etc/group | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "Sudoers config file and a list of users with sudo access:" >> $basedir/system_info.log
cat /etc/sudoers | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of ALL scheduled jobs:" >> $basedir/system_info.log
cat /etc/crontab | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of ALL scheduled jobs:" >> $basedir/system_info.log
cat /etc/cron.*/ | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of ALL systemd timers:" >> $basedir/system_info.log
systemctl status *timer | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of ALL scheduled jobs:" >> $basedir/system_info.log
cat /etc/*.d | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of CPU's properties and architecture as reported by OS (Double Check This Info!):" >> $basedir/system_info.log
lscpu | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of all block devices:" >> $basedir/system_info.log
lsblk -a | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of USB Devices and properties:" >> $basedir/system_info.log
lsusb -v | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of PCI devices and properties:" >> $basedir/system_info.log
lspci -v | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of SCSI devices and properties:" >> $basedir/system_info.log
lsscsi -s | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of hard drives and properties:" >> $basedir/system_info.log
fdisk -l | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of mountable partitions by GRUB:" >> $basedir/system_info.log
blkid | tee -a $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of mounted file systems:" >> $basedir/system_info.log
df -h | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "List of ALL mount points on the machine:" >> $basedir/system_info.log
cat /proc/mounts | tee -a  $basedir/system_info.log
echo "======================================================================================" >> $basedir/system_info.log
echo "COLLECTING SYSTEM INFORMATION... DONE!" | tee -a $basedir/system_info.log
echo "**************************************************************************************" >> $basedir/system_info.log
}

function main(){
    check_root
echo "**************************************************************************************" | tee -a $basedir/triageX.log
echo "Create triage collection from:" $server_name | tee -a $basedir/triageX.log
echo "Date:" $day | tee -a $basedir/triageX.log
echo " "
#Collect Linux Memory Image using Microsoft's AVML tool.
echo "COLLECTING MEMORY IMAGE WITH MICROSOFT'S AVML...PLEASE WAIT" | tee -a $basedir/triageX.log
./avml $basedir/memory.mem
echo "COLLECTING MEMORY IMAGEN...DONE!!!" | tee -a $basedir/triageX.log
echo "COLLECTING FILE TIMELINE...timeline.txt....PLEASE WAIT" | tee -a $basedir/triageX.log
echo -e "Access date;Access time;Modify date;Modify time;Create date;Create time;Permissions;UID;Username;GID;Groupname;Size;File" >> $basedir/timeline.txt
find / -path /mnt -prune -o -printf "%Ax;%AT;%Tx;%TT;%Cx;%CT;%m;%U;%u;%G;%g;%s;%p\n" 2>/dev/null  >> $basedir/timeline_file.txt
echo "COLLECTING FILE TIMELINE...timeline.txt....DONE!!!" | tee -a $basedir/triageX.log
}

main



