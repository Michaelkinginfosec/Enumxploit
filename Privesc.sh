#!/bin/bash

function create_hash(){
    # Prompt the user to enter a password
    read -p "Enter the password to create hash: " password
    
    # Use mkpasswd to generate a hash of the entered password
    hash=$(mkpasswd "$password")

    # Print the generated hash to the screen
    echo "Generated hash: $hash"
}

function crack_hash(){
    echo "Create a hash.txt file and save the hash"
    read -p "Enter the path to the hash.txt file(/path/to/hash.txt): " hash_file
    read -p "Enter the path to the wordlist file/path/to/wordlist): " wordlist_file
    john --wordlist=$wordlist_file $hash_file

}
function compile_suid(){
    gcc -o exploit exploit.c 
    sudo python3 http.server 80
}
function ssh_private(){
    cd ~
    mkdir .ssh
    cd .ssh
    touch root_key
    echo "paste the private key in text editor"
    sleep 5
    nano root_key
    chmod 600 root_key
    read -p "enter ip address of target machine" ip
    ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@$ip
}


while true
do 
    echo "[1] Create a hash for a password"
    echo "[2] Crack hash password"
    echo "[3] Compile suid exploit"
    echo "[4] Private ssh key"
    echo "[5] Exit"
    read -p "What would you like to do?: " option
     
    if [ "$option" == "1" ]
    then
        create_hash
    elif [ "$option" == "2" ]
    then
        crack_hash
    elif [ "$option" == "3" ]
    then
        compile_suid
        echo -e "\n"
        echo "starting python server"
        python3 -m http.server 80
    elif [ "$option" == "4" ]
    then
        ssh_private
    elif [ "$option" == "5" ]
    then
        exit
    else 
        echo "Invalid Input"
        exit
    fi
done
