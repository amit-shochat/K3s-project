#!/bin/bash 


##############
## Fucntion ##
##############

##Var
ROOT_FOLDER=`pwd`


check_system () { 
    CPU_Architecture=`dpkg --print-architecture`
    Distributor=`lsb_release -d | awk '{print $2}'`
    Release=`lsb_release -r | awk '{print $2}'`
}

get_install_mode () {
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


k3s_settings_file () {
	read -e -p "`echo -e 'Enter filename, use tab for completion:\n(e.g. file path - "/home/USERNAME/file") \nfilename\b> '`" filename
	SETTING_FILE="`realpath -s "$filename"`"

	element_num=`cat $SETTING_FILE | jq '. | length'`
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
		echo -e "\nList of the empty var in $filename: \n$(for i in "${empty[@]}"; do echo ">> $i" ; done)"
	fi

	#Ansible info
	ANSIBLE_INSTALL="`jq -r '.AnsibleSettinges.InstallAnsible' $SETTING_FILE`"
	CREATE_SSH_KEY="`jq -r '.AnsibleSettinges.CreateSshKey' $SETTING_FILE`"
	PASS_FOR_USER="`jq -r '.AnsibleSettinges.PassForUser' $SETTING_FILE`"
	ANSIBLE_NODE_USER="`jq -r '.AnsibleSettinges.WorkerUser' $SETTING_FILE`"
	ANSIBLE_WORKER_IP=("`jq -r '.AnsibleSettinges.WorkerIp' K3s-settings.json`")
	
	# Kubernetes info
	INSTALL_K3S_VERSION="`jq -r '.KubernetesOption.K3sVersion' $SETTING_FILE`"
	K3S_EXTRA_ARG="`jq -r '.KubernetesOption.ExtraSettings' $SETTING_FILE`"
	K3S_TIME_ZONE="`jq -r '.KubernetesOption.TimeZone' $SETTING_FILE`"
	
	#ArgocdCD ifno
	ARGOCD_VERSION="`jq -r '.ArgoCDSettings.ArgoCDVersion' $SETTING_FILE`"		
	ARGOCD_NAMESPACE="`jq -r '.ArgoCDSettings.ArgoCDNamespace' $SETTING_FILE`"
	ARGOCD_INSTALL_CLI="`jq -r '.ArgoCDSettings.InstallArgoCDCli' $SETTING_FILE`"
	ARGOCD_CLI_VERSION="`jq -r '.ArgoCDSettings.CliVersion' $SETTING_FILE`"
	ARGOCD_ADMIN_PASSWORD="`jq -r '.ArgoCDSettings.ArgoCDAdminPassword' $SETTING_FILE`"

	#Cert-manger info 
	CERT_MANAGER_INSTALL="`jq -r '.CertManagerSettings.InstallCertManager' $SETTING_FILE`"
	CERT_MANAGER_VERSION="`jq -r '.CertManagerSettings.CertMangetVersion' $SETTING_FILE`"
	CERT_MANAGER_LOCAL_DOMAIN_NAME="`jq -r '.CertManagerSettings.LocalDomainName' $SETTING_FILE`"
	CERT_MANAGER_CREATE_ROOT_CA="`jq -r '.CertManagerSettings.CreateRootCA' $SETTING_FILE`"

	# Letsencrypt info
	LETSENCRYPT_APPLY="`jq -r '.LetsEncrypt.ApllyLetsEncrypt' $SETTING_FILE`"
	LETSENCRYPT_EMAIL="`jq -r '.LetsEncrypt.LetsEncryptEmail' $SETTING_FILE`"

	# Duckdns info
	DUCKDNS_APPLY="`jq -r '.DuckDns.ApllyDuckDns' $SETTING_FILE`"
	DUCKDNS_TOKEN="`jq -r '.DuckDns.DuckDnsToken' $SETTING_FILE`"
	DUCKDNS_SUB_DOMAIN="`jq -r '.DuckDns.DuckDnsSubDomain' $SETTING_FILE`"

	#MetalLB info
	METALLB_INSTALL="`jq -r '.MetalLBSettings.InstallMetallLB' $SETTING_FILE`"
	METALLB_VERSION="`jq -r '.MetalLBSettings.MetalLBVersion' $SETTING_FILE`"
	METALLB_IP_RANG="`jq -r '.MetalLBSettings.MetalLBIpRang' $SETTING_FILE`"

	#Ingress-Nginx info
	INGRESS_NGINX_INSTALL="`jq -r '.IngressNginxSettings.InastallIngressNginx' $SETTING_FILE`"
	INGRESS_NGINX_VERSION="`jq -r '.IngressNginxSettings.IngressNginxVersion' $SETTING_FILE`"

	LONGHORN_VERSION="`jq -r '.LonghornSettings.LonghornVersion' $SETTING_FILE`"

}

install_pack () {
    if [ "$Distributor" = "Ubuntu" ]; then
        echo "install Pack: git ssh jq curl apt-transport-https apache2-utils Helm open-iscsi nfs-common " 
		sudo apt-get update && sudo apt-get upgrade -y  1> /dev/null
        curl -s https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg &>/dev/null
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list &> /dev/null
        sudo apt-get update &> /dev/null
        sudo apt-get install -y git ssh jq curl apt-transport-https apache2-utils helm open-iscsi nfs-common &> /dev/null

    elif  [ "$Distributor" = "Centos" ]; then
        yum update && yum upgrade 
        yum install git ssh jq curl
    fi
}

configuring_ansible () {
	if [ $ANSIBLE_INSTALL == "true" ]; then
		echo -e "\nInstall and configuration ansible"
		
		# Create Ansible folder for configured files 
		mkdir -p $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook
		
		# Insatall Pack 
		apt install -y  ansible sshpass &> /dev/null

		#Install ansible module
		sudo runuser -l  $(logname) -c "ansible-galaxy collection install ansible.posix"
		# Enter sudo pasowrd user for Ansible install
		if [ -z $PASS_FOR_USER ]; then 
			pass_var=`echo -e 'Please make sure theh master and nodes have a same user with the same password\nPlease provide the password (Just for the first ansible intall): \n\b> '`;while IFS= read -p "$pass_var" -r -s -n 1 letter ;do if [[ $letter == $'\0' ]];then break;fi;pass_var="*";PASS_FOR_USER+="$letter";done
			echo
		fi

		# Create an ssh key 
		if [ $CREATE_SSH_KEY == "true" ]; then
			echo "Create ssh Key and public" 
			runuser -l $(logname) -c 'ssh-keygen -q -b 2048 -t rsa -N "" -f ~/.ssh/id_rsa '
		fi

		# copy ssh to worker 
		for i in $ANSIBLE_WORKER_IP; do 
			sudo runuser -l  $(logname) -c "ssh-keyscan -H $i >> ~/.ssh/known_hosts"
			sudo runuser -l  $(logname) -c "echo "$PASS_FOR_USER" | sshpass ssh-copy-id $i &> /dev/null"
			echo "copy User: $(runuser -l $(logname) -c "ssh -i /home/$(logname)/.ssh/id_rsa $(logname)@$i uname -n")_$i"
		done

		# Configur Ansible hosts 
		echo "Configur ansible hosts"
		if [ -f /etc/ansible/hosts ]; then cp /etc/ansible/hosts /etc/ansible/hosts.bak; rm -rf /etc/ansible/hosts;fi
		echo -e "[kuberntes_node]" >> /etc/ansible/hosts
		for i in $ANSIBLE_WORKER_IP; do 
			echo -e "$(sudo runuser -l  $(logname) -c "ssh -i /home/$(logname)/.ssh/id_rsa $(logname)@$i uname -n") ansible_host=$i" >> /etc/ansible/hosts
		done
		
		# Update Playbook for user name 
		echo "Run Update playbook for pack update Worker node"
		sed "s/ANSIBLE_NODE_USER/$ANSIBLE_NODE_USER/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Ansible-Playbook/Playbook-update.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook/Playbook-update.yaml
		sed -i "s/ANSIBLE_NODE_USER/$ANSIBLE_NODE_USER/g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook/Playbook-update.yaml
		apt-get update && apt-get upgrade -y &> /dev/null
		sudo runuser -l  $(logname) -c "ansible-playbook $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook/Playbook-update.yaml -u $(logname) --private-key /home/$(logname)/.ssh/id_rsa --extra-vars "ansible_sudo_pass=$PASS_FOR_USER""
		echo "Finish install and configuration ansible" 
	fi
}

install_k3s () {
	echo -e "\nPreparing Host Provider "
	echo -e "selected installation mode $COMMISION_MODE\n"
	local k3s_flag=`which k3s`
	if [ -z $k3s_flag ]; then
		# Install k3s
		echo -e "Installing K3S"
		openssl rand -hex 10 > k3s_secret.txt
		curl https://releases.rancher.com/install-docker/20.10.sh | sh
		sleep 5 
		curl -sfL https://get.k3s.io | K3S_TOKEN=`cat k3s_secret.txt` INSTALL_K3S_VERSION="$INSTALL_K3S_VERSION" sh -s - server --docker --cluster-init --write-kubeconfig-mode 644 $K3S_EXTRA_ARG
		# If no multe node disabled CriticalAddonsOnly taint
		if [ $ANSIBLE_INSTALL == "false" ] && [ echo $INSTALL_K3S_VERSION | grep "CriticalAddonsOnly" ]; then
			kubectl taint node $(hostname) CriticalAddonsOnly=true:NoExecute-
		fi
		# check if K3S install and running
		if [ ! -z $k3s_flag ]; then
			echo -e "K3S Not installed properly\nPlease check your network connection and reinstall"
			exit 1
		else
			echo -e "Finished installing K3S"
		fi
		echo "Setting initial K3S configuration"
		# Install kubectl
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
		# wait for matric pod started 
		while [[ "$SEC" -lt 600 ]]; do let SEC++;if [[ $(kubectl -n kube-system get pods -l k8s-app=metrics-server -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') = "True" ]]; then unset SEC;break;fi;sleep 1;done
	fi

	# Ansible add nodes
	if [ $ANSIBLE_INSTALL == "true" ]; then
		echo "Install K3s Worker agent" 
		local K3S_TOKEN_KEY="`cat k3s_secret.txt`"
		local K3S_URL_IP="`hostname -I | awk '{print $1}'`"
		sed "s/K3S_URL_IP/$K3S_URL_IP/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Ansible-Playbook/Playbook-install_k3s-agent.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook/Playbook-install_k3s-agent.yaml
		sed -i "s/K3S_TOKEN_KEY/$K3S_TOKEN_KEY/g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook/Playbook-install_k3s-agent.yaml
		sed -i "s/K3S_EXTRA_ARG/$K3S_EXTRA_ARG/g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook/Playbook-install_k3s-agent.yaml
		sed -i "s/INSTALL_K3S_VERSION_NUM/$INSTALL_K3S_VERSION/g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook/Playbook-install_k3s-agent.yaml
		sudo runuser -l  $(logname) -c "ansible-playbook $ROOT_FOLDER/Configured_yamls/Argocd_application/Ansible-Playbook/Playbook-install_k3s-agent.yaml -u $(logname) --private-key /home/$(logname)/.ssh/id_rsa"
	fi
}

install_Argocd () { 
	# Add Argocd repo
	echo "Start install managment application"
	echo "install ArgoCD" 
	helm repo add argo https://argoproj.github.io/argo-helm &> /dev/null
	helm repo update &> /dev/null

	# install Argocd Helm chart
	ARGOCD_ADMIN_PASSWORD_BCRYPT=`htpasswd -nbBC 10 "" $ARGOCD_ADMIN_PASSWORD | tr -d ':\n' | sed 's/$2y/$2a/'`
	helm install argocd argo/argo-cd \
		--version $ARGOCD_VERSION \
		--namespace $ARGOCD_NAMESPACE \
		--create-namespace &> /dev/null 
	echo "Waiting for ArgoCD get Ready" 
	while [[ "$SEC" -lt 600 ]]; do let SEC++;if [[ $(kubectl -n argocd get pods -l app.kubernetes.io/name=argocd-server -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') = "True" ]]; then unset SEC;break;fi;sleep 1;done
	while [[ "$SEC" -lt 600 ]]; do let SEC++;if [[ $(kubectl -n argocd get pods -l app.kubernetes.io/name=argocd-dex-server -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') = "True" ]]; then unset SEC;break;fi;sleep 1;done
	if [ $ARGOCD_INSTALL_CLI == "true" ]; then
		curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/download/$ARGOCD_CLI_VERSION/argocd-linux-$CPU_Architecture
		chmod +x /usr/local/bin/argocd
	fi
	echo -e "Install ArgoCD Project's" 

	# Create Argocd_app folder for configured files 
	mkdir -p $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd

	# Copy and configuring files 
	cp $ROOT_FOLDER/Default_yamls/Argocd_application/Argocd/Infrastructure.project.yaml $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Infrastructure.project.yaml
	kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Infrastructure.project.yaml	 
	echo "Finish install ArgoCD"
} 

install_cert_manager () {
	if [ $CERT_MANAGER_INSTALL == "true" ]; then
		echo "install Cert-manager" 

		# Create Argocd_app folder for configured files 
		mkdir -p $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager
		
		# Edit Cert-manager application yaml
		sed "s/CERT_MANAGER_VERSION/$CERT_MANAGER_VERSION/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Cert-manager/Cert-manager.application.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Cert-manager.application.yaml
		
		# Wiat until all Cert-manager pod are running
		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Cert-manager.application.yaml
		while [[ "$SEC" -lt 600 ]]; do 
			let SEC++
			if [[ "$SEC" -eq 200 ]] && [[ $(kubectl  -n  argocd get applications cert-manager -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications cert-manager -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then
				kubectl delete -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Cert-manager.application.yaml
				kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Cert-manager.application.yaml
			fi
			if [[ $(kubectl  -n  argocd get applications cert-manager -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications cert-manager -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
				unset SEC
				break
			fi
			sleep 1
		done
		
		# Create 
		# Create Self-signed issuer for rootCA
		cp $ROOT_FOLDER/Default_yamls/Argocd_application/Cert-manager/selfsigned.issuer.yaml $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/selfsigned.issuer.yaml
		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/selfsigned.issuer.yaml

		# Create local-domain ClusterIssuer and root CA Certificate
		sed "s/CERT_MANAGER_LOCAL_DOMAIN_NAME/$CERT_MANAGER_LOCAL_DOMAIN_NAME/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Cert-manager/Local-domain.ClusterIssuer_and_certificate.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Local-domain.ClusterIssuer_and_certificate.yaml
		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Local-domain.ClusterIssuer_and_certificate.yaml

		#Create web Python server Deployment\server\ingress to get TLS cert
		sed "s/CERT_MANAGER_LOCAL_DOMAIN_NAME/$CERT_MANAGER_LOCAL_DOMAIN_NAME/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Cert-manager/Python-server-for-get-tls.Deployment.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Python-server-for-get-tls.Deployment.yaml
		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Python-server-for-get-tls.Deployment.yaml
		echo "Finish Deploy Python-cert-server"
		
		# Deploy letsencrypt ClusterIssuet
		if [ $LETSENCRYPT_APPLY == "true" ]; then
			echo "Deploy letsencrypt ClusterIssuet"
			sed "s/LETSENCRYPT_EMAIL/$LETSENCRYPT_EMAIL/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Cert-manager/Letsencrypt.ClusterIssuer-production.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Letsencrypt.ClusterIssuer-production.yaml
			kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Cert-manager/Letsencrypt.ClusterIssuer-production.yaml
			echo "Finish Deploy letsencrypt ClusterIssuet"
		fi
		echo "Finish install Cert-manager"
	fi
}

install_metallb () {
	if [ $METALLB_INSTALL == "true" ]; then
		echo "Deploy Metallb"

		# Create Metallb folder for configured files 
		mkdir -p $ROOT_FOLDER/Configured_yamls/Argocd_application/Metallb

		# Deploy Metallb and with until running 
		sed "s/METALLB_VERSION/$METALLB_VERSION/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Metallb/Metallb.application.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Metallb/Metallb.application.yaml
		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Metallb/Metallb.application.yaml
		while [[ "$SEC" -lt 600 ]]; do 
			let SEC++
			if [[ "$SEC" -eq 2000 ]] || [[ $(kubectl  -n  argocd get applications metallb -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications metallb -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then 
				kubectl delete -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Metallb/Metallb.application.yaml
				kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Metallb/Metallb.application.yaml
			fi
			if [[ $(kubectl  -n  argocd get applications metallb -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications metallb -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
				unset SEC
				break
			fi
			sleep 1
		done

		# Deploy Metallb IP rang 
		sed "s/METALLB_IP_RANG/$METALLB_IP_RANG/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Metallb/Metallb.ip-reang.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Metallb/Metallb.ip-reang.yaml
		
		# Apply Metallb ip range LB
		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Metallb/Metallb.ip-reang.yaml
		echo "Finish Deploy Metallb"
	fi
}
install_ingress_nginx () {

	# Insatll ingress-nginx helm 
	if [ $INGRESS_NGINX_INSTALL == "true" ]; then
		echo "Deploy Ingress Nginx"

		# Create Metallb folder for configured files 
		mkdir -p $ROOT_FOLDER/Configured_yamls/Argocd_application/Ingress-nginx

		# copy and configured Ingress-nginx file 
		sed "s/INGRESS_NGINX_VERSION/$INGRESS_NGINX_VERSION/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Ingress-nginx/Ingress-nginx.application.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Ingress-nginx/Ingress-nginx.application.yaml
		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Ingress-nginx/Ingress-nginx.application.yaml
		while [[ "$SEC" -lt 600 ]]; do 
			let SEC++
			if [[ "$SEC" -eq 2000 ]] || [[ $(kubectl  -n  argocd get applications ingress-nginx -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications ingress-nginx -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then 
				kubectl delte -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Ingress-nginx/Ingress-nginx.application.yaml
				kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Ingress-nginx/Ingress-nginx.application.yaml
			fi
			if [[ $(kubectl  -n  argocd get applications ingress-nginx -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications ingress-nginx -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
				unset SEC
				break
			fi
			sleep 1
		done
		echo "Finish Deploy Ingress Nginx"
	fi
}

update_argo_chart() {

	# Deploy Argocd to Argo UI 
	sed "s/ARGOCD_VERSION/$ARGOCD_VERSION/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Argocd/Argocd-application.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Argocd-application.yaml
	sed -i "s/CERT_MANAGER_LOCAL_DOMAIN_NAME/$CERT_MANAGER_LOCAL_DOMAIN_NAME/g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Argocd-application.yaml
	sed -i "s/ARGOCD_ADMIN_PASSWORD_BCRYPT/$ARGOCD_ADMIN_PASSWORD_BCRYPT/g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Argocd-application.yaml
	kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Argocd-application.yaml
	while [[ "$SEC" -lt 600 ]]; do 
		let SEC++
		if [[ "$SEC" -eq 200 ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then
			echo -e "\n Argocd apllication status unknown, delete and try agin"
			kubectl delete -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Argocd-application.yaml
			kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Argocd-application.yaml
		fi
		if [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
			unset SEC
			break
		fi
		sleep 1
	done
}

install_longhorn() {

	# Deploy Longhorn-CSI
	mkdir -p $ROOT_FOLDER/Configured_yamls/Argocd_application/Longhorn
	sed "s/LONGHORN_VERSION/$LONGHORN_VERSION/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Longhorn/longhor.application.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Longhorn/longhor.application.yaml
	sed -i "s/CERT_MANAGER_LOCAL_DOMAIN_NAME/$CERT_MANAGER_LOCAL_DOMAIN_NAME/g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Longhorn/longhor.application.yaml
	sed -i "s/ARGOCD_ADMIN_PASSWORD_BCRYPT/$ARGOCD_ADMIN_PASSWORD_BCRYPT/g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Longhorn/longhor.application.yaml
	kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Longhorn/longhor.application.yaml
	cp $ROOT_FOLDER/Default_yamls/Argocd_application/Longhorn/Longhorn.sa-role.yaml $ROOT_FOLDER/Configured_yamls/Argocd_application/Longhorn/Longhorn.sa-role.yaml
	kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Longhorn/Longhorn.sa-role.yaml

	# while [[ "$SEC" -lt 600 ]]; do 
	# 	let SEC++
	# 	if [[ "$SEC" -eq 200 ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then
	# 		echo -e "\n Argocd apllication status unknown, delete and try agin"
	# 		kubectl delete -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Argocd-application.yaml
	# 		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Argocd/Argocd-application.yaml
	# 	fi
	# 	if [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
	# 		unset SEC
	# 		break
	# 	fi
	# 	sleep 1
	# done
}

install_duckdns () {
	# Deploy DockDns for update IP on FQDN 
	if [ $DUCKDNS_APPLY == "true" ]; then
		echo "Deploy Duckdns app for update IP on FQDN"

		# Create Metallb folder for configured files 
		mkdir -p $ROOT_FOLDER/Configured_yamls/Argocd_application/Duckdns

		# Create NS Dockdns
		kubectl create ns duckdns

		# Create TOKEN secret for Dockdns
		kubectl -n duckdns create secret generic duckdns-token --from-literal=token=$DUCKDNS_TOKEN

		# Configued deployment files and apply to cluster 
		sed "s/DUCKDNS_SUB_DOMAIN/$DUCKDNS_SUB_DOMAIN/g" $ROOT_FOLDER/Default_yamls/Argocd_application/Duckdns/duckdns.deployment.yaml > $ROOT_FOLDER/Configured_yamls/Argocd_application/Duckdns/duckdns.deployment.yaml
		sed -i "s-K3S_TIME_ZONE-$K3S_TIME_ZONE-g" $ROOT_FOLDER/Configured_yamls/Argocd_application/Duckdns/duckdns.deployment.yaml
		kubectl apply -f $ROOT_FOLDER/Configured_yamls/Argocd_application/Duckdns/duckdns.deployment.yaml
		echo "Finish Deploy Duckdns app "
	fi
} 
uninstall_all () {
    # Uninstall K3s
    k3s-uninstall.sh &> /dev/null 
	ansible all -m shell -a 'k3s-agent-uninstall.sh' -u $(logname) --private-key /home/$(logname)/.ssh/id_rsa &> /dev/null

	# Remove kubectl 
	sudo snap remove kubectl &> /dev/null

	# Remove .kube folder
	rm -rf ~/.kube &> /dev/null
	rm -rf /home/$(logname)/.kube &> /dev/null

	# uninstall Helm 
	apt purge helm --yes &> /dev/null

	# Remove yaml folder 
	rm -rf $ROOT_FOLDER/Configured_yamls/Argocd_application &> /dev/null

	echo -e "Finish remove all deployment and file" 

}

###################
## Installation ###
###################


# Check if user is Root
[ "$UID" -eq 0 ] || { echo -e "\nThis script must be run as root.\nPlease use sudo user and try again"; exit 1;}

COMMISION_MODE=$(get_install_mode)  
case $COMMISION_MODE in 
	Master)
        check_system
        install_pack
        k3s_settings_file
		configuring_ansible
        install_k3s
		install_Argocd
		install_cert_manager
		install_metallb
		install_ingress_nginx
		install_duckdns
		update_argo_chart
		install_longhorn
		chown $(logname):$(logname) -R $ROOT_FOLDER/Configured_yamls 
	;;
	Node)
		# create log file
	;;
	Uninstall)
		# Import_file_settings
		uninstall_all 
	;;
	Quit)
		echo -e "\nHave a nice day"
		exit 1
	;;
esac
