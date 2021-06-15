#!/bin/sh -x

#./docker-cross-network-routing.sh
#KUBECONFIG="$(k3d kubeconfig write cluster0)" kubectl -n network get secret/cacerts -o yaml | KUBECONFIG="$(k3d kubeconfig write cluster1)" kubectl replace -f-

KUBECONFIG="$(k3d kubeconfig write cluster1)" kubectl -n network get secret/istio-remote-secret-cluster1 -o yaml | KUBECONFIG="$(k3d kubeconfig write cluster0)" kubectl -n network create -f-
KUBECONFIG="$(k3d kubeconfig write cluster0)" kubectl -n network get secret/istio-remote-secret-cluster0 -o yaml | KUBECONFIG="$(k3d kubeconfig write cluster1)" kubectl -n network create -f-

#KUBECONFIG="${HOME}/.local/share/kubedee/clusters/cluster1/kubeconfig/admin.kubeconfig" kubectl -n network get secret/istio-remote-secret-cluster1 -o yaml | \
#  KUBECONFIG="${HOME}/.local/share/kubedee/clusters/cluster0/kubeconfig/admin.kubeconfig" kubectl -n network create -f-
#KUBECONFIG="${HOME}/.local/share/kubedee/clusters/cluster0/kubeconfig/admin.kubeconfig" kubectl -n network get secret/istio-remote-secret-cluster0 -o yaml | \
#  KUBECONFIG="${HOME}/.local/share/kubedee/clusters/cluster1/kubeconfig/admin.kubeconfig" kubectl -n network create -f-

NS="${NS:-sample}"

for i in $(seq 0 1); do
  export KUBECONFIG="$(k3d kubeconfig write "cluster${i}")"
  #export KUBECONFIG="${HOME}/.local/share/kubedee/clusters/cluster${i}/kubeconfig/admin.kubeconfig"
  kubectl create ns "${NS}"
  kubectl label ns "${NS}" istio-injection=enabled
  kubectl -n "${NS}" apply -f "${MYDIR:+${MYDIR}/}../charts/istio/samples/helloworld/helloworld.yaml" -l service=helloworld
  kubectl -n "${NS}" apply -f "${MYDIR:+${MYDIR}/}../charts/istio/samples/helloworld/helloworld.yaml" -l version="v$((${i}+1))"
  kubectl -n "${NS}" apply -f "${MYDIR:+${MYDIR}/}../charts/istio/samples/sleep/sleep.yaml"
  unset KUBECONFIG
done
