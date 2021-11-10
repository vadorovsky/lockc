#!/bin/bash
#shellcheck disable=SC2145,SC2016
log()   { (>&1 echo -e "$@") ; }
cmd()   { log "$@" ; }
info()  { log "[ INFO ] $@" ; }
error() { (>&2 echo -e "[ ERROR ] $@") ;}

if [ -z "${TR_MASTER_IPS}" ] || [ -z "${TR_USERNAME}" ]; then
    error '$TR_MASTER_IPS $TR_USERNAME must be specified'
    exit 1
fi

sleep 5

info "### Run following commands to bootstrap Kubernetes cluster:\\n"
cmd ""

i=0
for MASTER in $TR_MASTER_IPS; do
    cmd "ssh -o 'StrictHostKeyChecking no' -l ${TR_USERNAME} ${MASTER} /bin/bash <<EOF"
    cmd ""
    
    if [ $i -eq "0" ]; then
        cmd "  sudo kubeadm init --cri-socket /run/containerd/containerd.sock --control-plane-endpoint ${MASTER}:6443 | tee kubeadm-init.log"
        cmd ""
        cmd "  mkdir -p /home/${TR_USERNAME}/.kube"
        cmd "  sudo cp /etc/kubernetes/admin.conf /home/${TR_USERNAME}/.kube/config"
        cmd "  sudo chown ${TR_USERNAME}:users /home/${TR_USERNAME}/.kube/config"
        cmd "EOF"

        ssh -o 'StrictHostKeyChecking no' -l ${TR_USERNAME} ${MASTER} /bin/bash <<-EOF
          sudo kubeadm init --cri-socket /run/containerd/containerd.sock --control-plane-endpoint ${MASTER}:6443 | tee kubeadm-init.log
          mkdir -p /home/${TR_USERNAME}/.kube
          sudo cp /etc/kubernetes/admin.conf /home/${TR_USERNAME}/.kube/config
          sudo chown ${TR_USERNAME}:users /home/${TR_USERNAME}/.kube/config
EOF

        cmd ""
        export KUBEADM_JOIN=`ssh -l ${TR_USERNAME} ${MASTER} tail -n2 kubeadm-init.log`
        export KUBEADM_CMD=`echo $KUBEADM_JOIN | sed -e 's/\\\ //'`
        echo $KUBEADM_CMD
    else
        cmd ""
        cmd " sudo kubeadm join"
        cmd "EOF"
        cmd ""
    fi
    ((++i))
done

i=0
for WORKER in $TR_WORKER_IPS; do
    cmd "ssh -o 'StrictHostKeyChecking no' -l ${TR_USERNAME} ${WORKER} sudo ${KUBEADM_CMD}"
    ssh -o 'StrictHostKeyChecking no' -l ${TR_USERNAME} ${WORKER} sudo ${KUBEADM_CMD}
    ((++i))
done

cmd ""
cmd "scp ${TR_USERNAME}@${MASTER}:/home/${TR_USERNAME}/.kube/config ./admin.conf"
cmd "export KUBECONFIG=`pwd`/admin.conf"
cmd ""

scp ${TR_USERNAME}@${MASTER}:/home/${TR_USERNAME}/.kube/config ./admin.conf
export KUBECONFIG=`pwd`/admin.conf
kubectl get nodes

cmd ""
cmd "WARNING!!! To start with K8s cluster please run following command:"
cmd "export KUBECONFIG=`pwd`/admin.conf"
cmd ""
