#!/bin/bash 


##############
## Fucntion ##
##############

Check_system () { 
    CPU_Architecture=`uname -m`
    Distributor=`lsb_release -d | awk '{print $2}'`
    Release=`lsb_release -r | awk '{print $2}'`
}

Install_pack () {
    if [ "$Distributor" = "Ubuntu" ]; then 
        apt update && apt upgrade
        apt install git ssh jq curl
    elif  [ "$Distributor" = "Centos" ]; then
        yum update && yum upgrade 
        yum install git ssh jq curl
    fi
}

Get_install_mode () {
	PS3='Please select Install mode: '
	options=("Master" "Node" "Uninstall" "Quit")
	select opt in "${options[@]}"
	do
		case $opt in
			"Master")
				echo $opt
				break
				;;
			"Node")
				echo $opt
				break
				;;
			"Uninstall")
				echo $opt
				break
				;;	
			"Quit")
				break
				;;
			*) 
			echo "invalid option $REPLY" >&2
			;;
		esac
	done
}


Import_file_settings () {
	while [[ -z $IMPORT_FILE_SETTINGS ]]; do read -rep $'Do you want to import file settings? (YES/NO) ' IMPORT_FILE_SETTINGS; 
		case $IMPORT_FILE_SETTINGS in
		Y | y |YES | Yes | yes)
			IMPORT_FILE_SETTINGS="YES"
			break
			;;
		N | n |NO | No | no)
			IMPORT_FILE_SETTINGS="NO"
			break
			;;
		*) echo "invalid option"; unset IMPORT_FILE_SETTINGS;
			;;
		esac
	done
}


K3s_settings_file () {
	read -e -p "`echo -e 'Enter filename, use tab for completion:\n(e.g. file path - "/home/USERNAME/file") \nfilename\b> '`" filename
	SETTING_FILE="`realpath -s "$filename"`"

	element_num=`cat config/Arc-setting.json | jq '. | length'`
	X=0
	empty=()
	while [ $X -le "$(($element_num-1))" ]; do
			element_name=`cat $filename | jq -r ". | keys[$X]"`
			key_num=`cat $filename | jq -r ".$element_name" | jq '. | length'`
			Y=0
			while [ $Y -le "$(($key_num-1))" ]; do
					if [ "$(cat $filename | jq -r ".$element_name | to_entries[$Y] | [.key, .value] | @tsv" | awk '{print $2}')" = "" ]; then
							empty+=(`cat $filename | jq -r ".$element_name | to_entries[$Y] | [.key, .value] | @tsv" | awk '{print $1}'`)
					fi
					let Y++
			done

			let X++
	done

	if (( ${#empty[@]} )); then
		k3s-uninstall.sh &> /dev/null
		echo -e "\nList of the empty var in $filename: \n$(for i in "${empty[@]}"; do echo ">> $i" ; done) \n\nPlease fill them and start agine"
		exit 1
	fi

	# Kubernetes info
	K3S_EXTRA_ARG="`jq -r '.KubernetesOption.K3sVersion' $SETTING_FILE`"
	INSTALL_K3S_VERSION="`jq -r '.KubernetesOption.ExtraSettings' $SETTING_FILE`"

}

Install_k3s () {
	echo -e "\nPreparing Host Provider "
	echo -e "selected installation mode $COMMISION_MODE\n"
	ROOT_FOLDER=`pwd`
	local k3s_flag=`which k3s`
	if [ -z $k3s_flag ]; then
		# Install rancher's k3s
		# echo "Installing Docker"
		# curl https://releases.rancher.com/install-docker/19.03.sh | sh
		echo -e "Installing K3S"
		curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="" sh -s - $K3S_EXTRA_ARG
		# check if K3S install and running
		if [ ! -z $k3s_flag ]; then
			echo -e "K3S Not installed properly\nPlease check your network connection and reinstall"
			exit 1
		else
			echo -e "Finished installing K3S"
		fi
		echo "Setting initial K3S configuration"
		# Install kubectl
		sudo apt-get update  &> /dev/null
		sudo apt-get install -y apt-transport-https ca-certificates curl  &> /dev/null
		sudo snap install kubectl --classic   &> /dev/null
		kubectl completion bash > /tmp/kubectl_completion
		sudo mv /tmp/kubectl_completion /etc/bash_completion.d/kubectl_completion
		source /etc/bash_completion.d/kubectl_completion
		echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> ~/.bashrc
		echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> /home/$(logname)/.bashrc
		mkdir ~/.kube 2> /dev/null 
		mkdir /home/$(logname)/.kube 2> /dev/null 
		k3s kubectl config view --raw > ~/.kube/config
		k3s kubectl config view --raw > /home/$(logname)/.kube/config
		chown $(logname):$(logname) /home/$(logname)/.kube
		chown -R $(logname):$(logname) /home/$(logname)/.kube/*
		sed -n 'H;${x;s/^\n//;s/ExecStartPre .*$/ExecStartPre=sleep 10\n&/;}' /etc/systemd/system/k3s.service
		sleep 2 
		echo -e "Finished configure K3S"
	fi
}

##################
## Installation###
##################


[ "$UID" -eq 0 ] || { echo -e "\nThis script must be run as root.\nPlease use sudo user and try again"; exit 1;}


COMMISION_MODE=$(Get_install_mode)  
case $COMMISION_MODE in 
	Master)
		# create log file
        Check_system
        Install_pack
        Get_install_mode
        Import_file_settings
        K3s_settings_file
        Install_k3s
	;;
	Node)
		# create log file
	;;
	Uninstall)
		k3s-uninstall.sh &> /dev/null
	;;
	Quit)
		echo -e "\nHave a nice day"
		exit 1
	;;
esac
