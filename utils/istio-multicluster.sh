#!/bin/sh -x

#./docker-cross-network-routing.sh

STARTIDX=0 ENDIDX=1 CAIDX=0
for dstidx in $(seq "${STARTIDX}" "${ENDIDX}"); do
  DSTKUBE="$(k3d kubeconfig write "cluster${dstidx}")"  # DSTKUBE="${HOME}/.local/share/kubedee/clusters/cluster${dstidx}/kubeconfig/admin.kubeconfig"
  #KUBECONFIG="$(k3d kubeconfig write "cluster${CAIDX}")" kubectl -n network get secret/cacerts -o yaml | KUBECONFIG="${DSTKUBE}" kubectl replace -f-
  for srcidx in $(seq "${STARTIDX}" "${ENDIDX}"); do
    [ "${srcidx}" -ne "${dstidx}" ] || continue
    SRCKUBE="$(k3d kubeconfig write "cluster${srcidx}")"  # SRCKUBE="${HOME}/.local/share/kubedee/clusters/cluster${srcidx}/kubeconfig/admin.kubeconfig"
    KUBECONFIG="${SRCKUBE}" kubectl -n network get "secret/istio-remote-secret-cluster${srcidx}" -o yaml | KUBECONFIG="${DSTKUBE}" kubectl -n network create -f-
  done
done

NS="${NS:-sample}"

for i in $(seq "${STARTIDX}" "${ENDIDX}"); do
  export KUBECONFIG="$(k3d kubeconfig write "cluster${i}")"  # KUBECONFIG="${HOME}/.local/share/kubedee/clusters/cluster${i}/kubeconfig/admin.kubeconfig"
  kubectl create ns "${NS}"
  kubectl label ns "${NS}" istio-injection=enabled
  kubectl -n "${NS}" apply -f "${MYDIR:+${MYDIR}/}../charts/istio/samples/helloworld/helloworld.yaml" -l service=helloworld
  kubectl -n "${NS}" apply -f "${MYDIR:+${MYDIR}/}../charts/istio/samples/helloworld/helloworld.yaml" -l version="v$((${i}+1))"
  kubectl -n "${NS}" apply -f "${MYDIR:+${MYDIR}/}../charts/istio/samples/sleep/sleep.yaml"
  unset KUBECONFIG
done
