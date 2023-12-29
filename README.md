![image](https://github.com/jdangosto/triageX/assets/20812848/db287c23-69da-486f-86ea-e479baf21420)


# TriageX - Linux Triage Tool
Is a BASH shell script designed to collect evidences in an incident with Linux machines. The script uses native Linux commands to run.

The ideal would be to use the script on an external drive since it writes certain files and the memory file.

The script generates a directory where it will store the results of the execution.

TriageX generates a timeline in csv so that it can be parsed in any editor for analysis, gathers useful information about the system:
- Operating system information and statistics.
- Specific hardware information.
- Networking, Firewall, ARP, configurations and statistics.
- List of running processes.
- List of users, groups, and privileges.
- Gets a list of packages installed on the system (currently deb and rpm).
- Complete list of directories and files of the entire Linux system directory tree.

Make a compressed copy of the directories:
- home
- root
- var/log

Easily customizable to your needs.

Microsoft AVML is used to capture memory, which you can download from here:
- https://github.com/microsoft/avml/releases/download/v0.13.0/avml

AVML must be in the same directory as the triageX.sh script. Don't worry if you don't download AVML for memory acquisition, triageX will still work normally, but it won't perform a memory capture.

# Usage
To use it you just have to change the execution permissions to the script:
- chmod +x triageX.sh
- chmod +x avml

The script must be excute as root.

Once finished, you will obtain a directory with the name of the machine and the date/time of execution, inside you will find all the acquisition carried out for your investigation.

# Important

If you run triageX from the computer itself, make sure you have enough space on the computer to store the files, and if you run it with AVML the memory acquisition will take up almost the same space than the memory installed on the computer plus the adquisition files.
