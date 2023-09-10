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
	mkdir -p $ROOT_FOLDER/Argocd_app
	mkdir -p $ROOT_FOLDER/Cert-manager
	mkdir -p /tmp/file_to_delete
}

install_pack () {
    if [ "$Distributor" = "Ubuntu" ]; then
        sudo apt-get update  
        echo "install Pack: git ssh jq curl apt-transport-https apache2-utils" 
        apt install -y git ssh jq curl apt-transport-https apache2-utils &> /dev/null
        echo "Install Helm..."
        curl -s https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg &>/dev/null
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list &> /dev/null
        sudo apt-get update &> /dev/null
        sudo apt-get install -y helm &> /dev/null

    elif  [ "$Distributor" = "Centos" ]; then
        yum update && yum upgrade 
        yum install git ssh jq curl
    fi
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
		k3s-uninstall.sh &> /dev/null
		echo -e "\nList of the empty var in $filename: \n$(for i in "${empty[@]}"; do echo ">> $i" ; done) \n\nPlease fill them and start agine"
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

	#MetalLB info
	METALLB_INSTALL="`jq -r '.MetalLBSettings.InstallMetallLB' $SETTING_FILE`"
	METALLB_VERSION="`jq -r '.MetalLBSettings.MetalLBVersion' $SETTING_FILE`"
	METALLB_IP_RANG="`jq -r '.MetalLBSettings.MetalLBIpRang' $SETTING_FILE`"

	#Ingress-Nginx info
	INGRESS_NGINX_INSTALL="`jq -r '.IngressNginxSettings.InastallIngressNginx' $SETTING_FILE`"
	INGRESS_NGINX_VERSION="`jq -r '.IngressNginxSettings.IngressNginxVersion' $SETTING_FILE`"

}


configuring_ansible () {
	
	if [ $ANSIBLE_INSTALL == "true" ]; then
		# Insatall Pack 
		apt install -y  ansible sshpass &> /dev/null
		# Enter sudo pasowrd user for Ansible install
		if [ -z $PASS_FOR_USER ]; then 
			pass_var=`echo -e 'Please make sure theh master and nodes have a same user with the same password\nPlease provide the password (Just for the first ansible intall): \n\b> '`;while IFS= read -p "$pass_var" -r -s -n 1 letter ;do if [[ $letter == $'\0' ]];then break;fi;pass_var="*";PASS_FOR_USER+="$letter";done
			echo
		fi
		# Create an ssh key 
		if [ $CREATE_SSH_KEY == "true" ]; then
			echo "Create ssh Key and public" 
			runuser -l $(logname) -c 'ssh-keygen -q -b 2048 -t rsa -N "" -f ~/.ssh/id_rsa'  
		fi
		# copy ssh to worker 
		for i in $ANSIBLE_WORKER_IP; do 
			echo "copy $(logname) ssh key to worker"
			sudo runuser -l  $(logname) -c "echo "$PASS_FOR_USER" | sshpass ssh-copy-id $i "
		done
		# Configur Ansible hosts 
		echo "Install Ansible and Configuration"
		if [ -f /etc/ansible/hosts ]; then cp /etc/ansible/hosts /etc/ansible/hosts.bak; rm -rf /etc/ansible/hosts;fi
		echo -e "[kuberntes_node]" >> /etc/ansible/hosts
		for i in $ANSIBLE_WORKER_IP; do 
			echo -e "$(dig -x $i +short | sed 's/\.//') ansible_host=$i" >> /etc/ansible/hosts
		done

		# Update Playbook for user name 
		echo "Run Update playbook for pack update Worker node"
		sed -i "s/REPLACE_ME_USER/$ANSIBLE_NODE_USER/g" $ROOT_FOLDER/Ansible-Playbook/Playbook-update.yaml
		
		ansible-playbook $ROOT_FOLDER/Ansible-Playbook/Playbook-update.yaml -u $(logname) --private-key /home/$(logname)/.ssh/id_rsa 
	fi
}

install_k3s () {
	echo -e "\nPreparing Host Provider "
	echo -e "selected installation mode $COMMISION_MODE\n"
	local k3s_flag=`which k3s`
	if [ -z $k3s_flag ]; then
		# Install k3s
		echo -e "Installing K3S"
		curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$INSTALL_K3S_VERSION" sh -s - --write-kubeconfig-mode 644 $K3S_EXTRA_ARG
		# If no multe node disabled CriticalAddonsOnly taint
		# if [ $ANSIBLE_INSTALL == "false" ] && [ echo $INSTALL_K3S_VERSION | grep "CriticalAddonsOnly" ]
			
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
		while [[ "$SEC" -lt 600 ]]; do let SEC++;if [[ $(kubectl -n kube-system get pods -l k8s-app=metrics-server -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') = "True" ]]; then unset SEC;break;fi;sleep 1;done
	fi

	# Ansible add nodes
	if [ $ANSIBLE_INSTALL == "true" ]; then
		echo "Install K3s Worker agent" 
		local K3S_TOKEN="`cat /var/lib/rancher/k3s/server/node-token`"
		local K3S_URL="`hostname -I | awk '{print $1}'`"
		sed -i "s/REPLACE_ME_MASTER_IP/$K3S_URL/g" $ROOT_FOLDER/Ansible-Playbook/Playbook-install_k3s-agent.yaml
		sed -i "s/REPLACE_ME_TOKEN/$K3S_TOKEN/g" $ROOT_FOLDER/Ansible-Playbook/Playbook-install_k3s-agent.yaml
		ansible-playbook $ROOT_FOLDER/Ansible-Playbook/Playbook-install_k3s-agent.yaml -u $(logname) --private-key /home/$(logname)/.ssh/id_rsa
	fi

}

install_Argocd () { 
	# Add Argocd repo
	echo "Start install ArgoCD" 
	helm repo add argo https://argoproj.github.io/argo-helm &> /dev/null
	helm repo update &> /dev/null
	# install Argocd Helm chart 
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
		cat << EOF > $ROOT_FOLDER/Argocd_app/Infrastructure.project.yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: infrastructure
  namespace: argocd
spec:
  clusterResourceWhitelist:
  - group: '*'
    kind: '*'
  destinations:
  - namespace: '*'
    server: '*'
  sourceRepos:
  - '*'
EOF
	kubectl apply -f $ROOT_FOLDER/Argocd_app/Infrastructure.project.yaml	 
	echo "Finish install ArgoCD"
} 

install_Charts () {
	if [ $CERT_MANAGER_INSTALL == "true" ]; then 
		cat << EOF > $ROOT_FOLDER/Argocd_app/Cert-manager.application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: cert-manager
  namespace: argocd
spec:
  destination:
    namespace: cert-manager
    server: https://kubernetes.default.svc
  project: infrastructure
  source:
    chart: cert-manager
    helm:
      parameters:
        - name: installCRDs
          value: "true"
    repoURL: https://charts.jetstack.io
    targetRevision: $CERT_MANAGER_VERSION
  syncPolicy:
    automated:
       selfHeal: true
       prune: true
    syncOptions:
      - CreateNamespace=true
EOF
	kubectl apply -f $ROOT_FOLDER/Argocd_app/Cert-manager.application.yaml
	while [[ "$SEC" -lt 600 ]]; do 
		let SEC++
		if [[ "$SEC" -eq 200 ]] && [[ $(kubectl  -n  argocd get applications cert-manager -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications cert-manager -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then
			kubectl delete -f $ROOT_FOLDER/Argocd_app/Cert-manager.application.yaml
			kubectl apply -f $ROOT_FOLDER/Argocd_app/Cert-manager.application.yaml
		fi
		if [[ $(kubectl  -n  argocd get applications cert-manager -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications cert-manager -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
			unset SEC
			break
		fi
		sleep 1
	done

	# Create Self-signed crt for rootCA
	cat << EOF > $ROOT_FOLDER/Cert-manager/selfsigned.issuer.yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: selfsigned-issuer
  namespace: cert-manager
spec:
  selfSigned: {}
EOF
	kubectl apply -f $ROOT_FOLDER/Cert-manager/selfsigned.issuer.yaml

	# Create local-domain issuer 
	cat << EOF > $ROOT_FOLDER/Cert-manager/Local-domain.ClusterIssuer_and_certificate.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: rootca-selfsigned-crt
  namespace: cert-manager
spec:
  isCA: true
  commonName: $CERT_MANAGER_LOCAL_DOMAIN_NAME
  secretName: rootca-selfsigned-crt
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: local-domain-self-signed
  namespace: cert-manager
spec:
  ca:
    secretName: rootca-selfsigned-crt
EOF
	kubectl apply -f $ROOT_FOLDER/Cert-manager/Local-domain.ClusterIssuer_and_certificate.yaml
	fi

	if [ $METALLB_INSTALL == "true" ]; then
		cat << EOF > $ROOT_FOLDER/Argocd_app/Metallb.application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: metallb
  namespace: argocd
spec:
  project: infrastructure
  source:
    repoURL: https://metallb.github.io/metallb
    targetRevision: $METALLB_VERSION
    chart: metallb
    helm:
  destination:
    server: https://kubernetes.default.svc
    namespace: metallb-system
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
    automated:
      prune: true
      allowEmpty: true
      selfHeal: true
EOF
		kubectl apply -f $ROOT_FOLDER/Argocd_app/Metallb.application.yaml
		while [[ "$SEC" -lt 600 ]]; do 
			let SEC++
			if [[ "$SEC" -eq 2000 ]] || [[ $(kubectl  -n  argocd get applications metallb -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications metallb -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then 
				kubectl delete -f $ROOT_FOLDER/Argocd_app/Metallb.application.yaml
				kubectl apply -f $ROOT_FOLDER/Argocd_app/Metallb.application.yaml
			fi
			if [[ $(kubectl  -n  argocd get applications metallb -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications metallb -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
				unset SEC
				break
			fi
			sleep 1
		done

		cat << EOF > $ROOT_FOLDER/Argocd_app/Metallb.ip-reang.yaml
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: k3s-range
  namespace: metallb-system
spec:
  addresses:
  - $METALLB_IP_RANG
---

apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: k3s-range
  namespace: metallb-system
EOF
		kubectl apply -f $ROOT_FOLDER/Argocd_app/Metallb.ip-reang.yaml 
	fi

	# Insatll ingress-nginx helm 
	if [ $INGRESS_NGINX_INSTALL == "true" ]; then
		cat << EOF > $ROOT_FOLDER/Argocd_app/Ingress-nginx.application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ingress-nginx
  namespace: argocd
spec:
  project: infrastructure
  source:
    repoURL: https://kubernetes.github.io/ingress-nginx
    targetRevision: $INGRESS_NGINX_VERSION
    chart: ingress-nginx
    helm:
  destination:
    server: https://kubernetes.default.svc
    namespace: ingress-nginx
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
    automated:
      prune: true
      allowEmpty: true
      selfHeal: true
EOF
		kubectl apply -f $ROOT_FOLDER/Argocd_app/Ingress-nginx.application.yaml
		while [[ "$SEC" -lt 600 ]]; do 
			let SEC++
			if [[ "$SEC" -eq 2000 ]] || [[ $(kubectl  -n  argocd get applications ingress-nginx -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications ingress-nginx -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then 
				kubectl delte -f $ROOT_FOLDER/Argocd_app/Ingress-nginx.application.yaml
				kubectl apply -f $ROOT_FOLDER/Argocd_app/Ingress-nginx.application.yaml
			fi
			if [[ $(kubectl  -n  argocd get applications ingress-nginx -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications ingress-nginx -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
				unset SEC
				break
			fi
			sleep 1
		done

	fi

	#Add Argocd Helm 
	ARGOCD_ADMIN_PASSWORD_BCRYPT=`htpasswd -nbBC 10 "" $ARGOCD_ADMIN_PASSWORD | tr -d ':\n' | sed 's/$2y/$2a/'`
	cat << EOF > $ROOT_FOLDER/Argocd_app/Argocd-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: argocd
  namespace: argocd
spec:
  project: infrastructure
  source:
    repoURL: https://argoproj.github.io/argo-helm
    targetRevision: $ARGOCD_VERSION
    chart: argo-cd
    helm:
      values: | 
        server:
          ingress:
            enabled: true
            ingressClassName: "nginx"
            path: /
            hosts:
              - argo.$CERT_MANAGER_LOCAL_DOMAIN_NAME
            annotations:
              cert-manager.io/cluster-issuer: local-domain-self-signed
              kubernetes.io/tls-acme: "true"
              nginx.ingress.kubernetes.io/backend-protocol: HTTPS
              nginx.ingress.kubernetes.io/ssl-passthrough: "true"
            labels: {}
            tls: 
             - secretName: argo-crt
               hosts:
                 - argocd.$CERT_MANAGER_LOCAL_DOMAIN_NAME
      parameters:
      - name: "server.service.type"
        value: LoadBalancer
      - name: "configs.secret.argocdServerAdminPassword"
        value: $ARGOCD_ADMIN_PASSWORD_BCRYPT
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
    automated:
      prune: true
      allowEmpty: true
      selfHeal: true
EOF
		kubectl apply -f $ROOT_FOLDER/Argocd_app/Argocd-application.yaml

	while [[ "$SEC" -lt 600 ]]; do 
		let SEC++
		if [[ "$SEC" -eq 200 ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.sync.status}') = "Unknown" ]]; then
			kubectl delete -f $ROOT_FOLDER/Argocd_app/Argocd-application.yaml
			kubectl apply -f $ROOT_FOLDER/Argocd_app/Argocd-application.yaml
		fi
		if [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.health.status}') = "Healthy" ]] && [[ $(kubectl  -n  argocd get applications argocd -o 'jsonpath={..status.sync.status}') = "Synced" ]]; then 
			unset SEC
			break
		fi
		sleep 1
	done

}


uninstall_all () {
    # Uninstall K3s
    k3s-uninstall.sh &> /dev/null 
	ansible all -m shell -a 'k3s-agent-uninstall.sh' -u $(logname) --private-key /home/$(logname)/.ssh/id_rsa 

	# Remove kubectl 
	sudo snap remove kubectl &> /dev/null

	# Remove .kube folder
	rm -rf ~/.kube &> /dev/null
	rm -rf /home/$(logname)/.kube &> /dev/null

	# uninstall Helm 
	apt purge helm --yes &> /dev/null

}

###################
## Installation ###
###################


# Check if user is Root
[ "$UID" -eq 0 ] || { echo -e "\nThis script must be run as root.\nPlease use sudo user and try again"; exit 1;}


# helm_flag=`which helm`
# if [ -z $curl_flag ]; then
# 	echo "installing curl"
# 	curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg &> /dev/null
# 	echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list &> /dev/null
# 	apt update &> /dev/null
# 	sudo apt-get install helm -y &> /dev/null
# fi
COMMISION_MODE=$(get_install_mode)  
case $COMMISION_MODE in 
	Master)
		# create log file
        check_system
        install_pack
        # Import_file_settings
        k3s_settings_file
		configuring_ansible
        install_k3s
		install_Argocd
		install_Charts
	;;
	Node)
		# create log file
	;;
	Uninstall)
		# Import_file_settings
		k3s_settings_file
		uninstall_all 
	;;
	Quit)
		echo -e "\nHave a nice day"
		exit 1
	;;
esac
