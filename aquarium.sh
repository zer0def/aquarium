#!/bin/bash -e
[ ${SCRIPT_DEBUG:=1} -eq 0 ] && set -x

# inb4 someone comes out yelling they don't have coreutils installed
BINARY_DEPENDENCIES=(docker helm helmfile kubectl)

# currently installed resources' requests have a hard time fitting on sub-quad-thread machines
DEFAULT_WORKERS=$((4/$(nproc)))
[ ${DEFAULT_WORKERS} -lt 1 ] && DEFAULT_WORKERS=1

DEFAULT_PROXY_REGISTRIES=(
  gcr.io quay.io "registry.opensource.zalan.do"
)

HELMFILE_ARGS=()
KUBE_NOPROXY_SETTING=(
  '.cluster.local' '.svc'
#  '192.168.0.0/16' '172.16.0.0/12' '10.0.0.0/8'
)

K3D_OPTS=()
KUBEDEE_OPTS=()
K3D_LIB_MOUNTS_ALL=()
MYDIR="$(dirname $(readlink -f ${0}))"

string_join() { local IFS="$1"; shift; echo "$*"; }

install_docker_volume_plugin(){
  local PLUGIN_LS_OUT=$(docker plugin ls --format '{{.Name}},{{.Enabled}}' | grep -E "^${DOCKER_VOLUME_PLUGIN}")
  [ -z "${PLUGIN_LS_OUT}" ] && docker plugin install ${DOCKER_VOLUME_PLUGIN} DATA_DIR=${DOCKER_VOLUME_DIR:=/tmp/docker-loop/data}
  echo "Sleeping 3 seconds for docker-volume-loopback to launch…" && sleep 3
  [ "${PLUGIN_LS_OUT##*,}" != "true" ] && docker plugin enable ${DOCKER_VOLUME_PLUGIN} ||:
}

create_volumes(){
  local DOCKER_VOLUME_DRIVER
  : ${DOCKER_VOLUME_DRIVER:=${DOCKER_VOLUME_PLUGIN:-local}}
  [ -n "${DOCKER_VOLUME_PLUGIN}" ] && install_docker_volume_plugin
  local VOLUME_NAME
  for i in $(seq 0 ${NUM_WORKERS}); do
    [ ${i} -eq 0 ] && VOLUME_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-server" || VOLUME_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-worker-$((${i}-1))"
    docker volume create -d ${DOCKER_VOLUME_DRIVER} ${VOLUME_NAME} -o sparse=true -o fs=ext4 -o size=10GiB &>/dev/null
    K3D_OPTS+=('-v' "${VOLUME_NAME}:/var/lib/rancher/k3s@${VOLUME_NAME}")
    if [ ${OLD_K3S} -ne 0 ]; then
      docker volume create \
        -d ${DOCKER_VOLUME_DRIVER} \
        -o sparse=true \
        -o fs=ext4 \
        -o size=10GiB \
        ${VOLUME_NAME}-kubelet &>/dev/null
      K3D_OPTS+=('-v' "${VOLUME_NAME}-kubelet:/var/lib/kubelet@${VOLUME_NAME}")
    fi
  done
}

# common functions start
kata_pre::k3d(){
  # only qemu works for now
  K3D_OPTS+=(
    '-e' 'LD_LIBRARY_PATH=/lib'
    '-v' '/usr/lib/kata-containers:/usr/local/lib/kata-containers'
    '-v' '/usr/share/kata-containers:/usr/local/share/kata-containers'
    '-v' '/usr/share/qemu:/usr/local/share/qemu'
    '-v' "${MYDIR}/kata-containers/config:/usr/local/share/defaults/kata-containers"
  ) \
  && K3D_LIB_MOUNTS_ALL+=('-v /usr/lib/ld-linux-x86-64.so.2:/lib64/ld-linux-x86-64.so.2') \
  && for i in containerd-shim-kata-v2 kata-runtime qemu-system-x86_64 firecracker jailer cloud-hypervisor virtiofsd; do
    local _bin=$(type -p ${i}) || continue
    K3D_OPTS+=('-v' "$(readlink -f ${_bin}):/usr/local/bin/${i}")
    for j in $(ldd ${_bin} 2>/dev/null | awk '/ => / {print $1}'); do
      local _awk_lib_name="$(echo ${j##*/} | sed -e 's/\+/\\+/g')"
      [ -n "${j##*/}" ] || continue
      local _lib_host_path=$(ldconfig -p | awk "/${_awk_lib_name} \(libc6,x86-64.*) => / {print \$NF}")
      K3D_LIB_MOUNTS_ALL+=("-v ${_lib_host_path}:/lib/${j##*/}")
    done
  done \
  && for i in qemu fc clh; do
    # https://github.com/kata-containers/documentation/blob/master/how-to/containerd-kata.md
    # https://github.com/kata-containers/packaging/blob/master/kata-deploy/scripts/kata-deploy.sh
    K3D_OPTS+=('-v' "${MYDIR}/kata-containers/shims/containerd-shim-kata-${i}-${SHIM_VERSION}:/usr/local/bin/containerd-shim-kata-${i}-${SHIM_VERSION}")
    cat <<EOF >> ${CLUSTER_CONFIG_HOST_PATH}/config.toml.tmpl
[plugins.cri.containerd.runtimes.kata-${i}]
  runtime_type = "io.containerd.kata-${i}.${SHIM_VERSION}"
  #privileged_without_host_devices = true
[plugins.cri.containerd.runtimes.kata-${i}.options]
  ConfigPath = "/usr/local/share/defaults/kata-containers/configuration-${i}.toml"
EOF
  done \
  && cat <<EOF >> ${CLUSTER_CONFIG_HOST_PATH}/config.toml.tmpl
[plugins.cri.containerd.untrusted_workload_runtime]
  runtime_type = "io.containerd.kata.${SHIM_VERSION}"
  privileged_without_host_devices = true
[plugins.cri.containerd.untrusted_workload_runtime.options]
  ConfigPath = "/usr/local/share/defaults/kata-containers/configuration-qemu.toml"
EOF
}

kata_pre::kubedee(){
  :
}

kata_pre(){
  kata_pre::${K8S_RUNTIME}
}

registry_proxy_pre::k3d(){
  mkdir -p ${REGISTRY_PROXY_HOST_PATH} \
  && docker run --entrypoint '' --rm rancher/k3s:v${RUNTIME_VERSIONS[k3d]} cat /etc/ssl/certs/ca-certificates.crt > ${CLUSTER_CONFIG_HOST_PATH}/ssl/ca-certificates.crt \
  && K3D_OPTS+=(
    '-e' "HTTP_PROXY=http://${REGISTRY_PROXY_HOSTNAME}:3128"
    '-e' "HTTPS_PROXY=http://${REGISTRY_PROXY_HOSTNAME}:3128"
    '-e' "NO_PROXY=$(string_join , ${KUBE_NOPROXY_SETTING[@]})"
    '-v' "${CLUSTER_CONFIG_HOST_PATH}/ssl:/etc/ssl/certs"
  )
}

registry_proxy_pre::kubedee(){
  :
}

registry_proxy_pre(){
  registry_proxy_pre::${K8S_RUNTIME}
}

registry_proxy_post::common(){
  local REGISTRIES="${PROXY_REGISTRIES:=${DEFAULT_PROXY_REGISTRIES[@]}}" AUTH_REGISTRIES="${PROXY_REGISTRIES_AUTH}" TARGET_FILE="${1}"
  docker run -d \
    --name "${REGISTRY_PROXY_HOSTNAME}" \
    -v ${REGISTRY_PROXY_HOST_PATH}:/docker_mirror_cache \
    -e "REGISTRIES=${REGISTRIES}" \
    -e "AUTH_REGISTRIES=${AUTH_REGISTRIES}" \
    ${REGISTRY_PROXY_DOCKER_ARGS[@]} \
    ${REGISTRY_PROXY_REPO} &>/dev/null
  docker exec "${REGISTRY_PROXY_HOSTNAME}" /bin/sh -c 'until test -f /ca/ca.crt; do sleep 1; done; cat /ca/ca.crt' >> ${TARGET_FILE}
}

registry_proxy_post::k3d(){
  # arguably common part start
  REGISTRY_PROXY_DOCKER_ARGS+=('--network' "k3d-${CLUSTER_NAME}")
  registry_proxy_post::common ${CLUSTER_CONFIG_HOST_PATH}/ssl/ca-certificates.crt
  # arguably common part end
}

registry_proxy_post::kubedee(){
  local TMP_CA="$(mktemp)" TMP_CRIO_CONF="$(mktemp)"
  lxc file pull kubedee-${CLUSTER_NAME}-controller/etc/ssl/certs/ca-certificates.crt "${TMP_CA}"
  mkdir -p ${REGISTRY_PROXY_HOST_PATH}

  #lxc file pull kubedee-${CLUSTER_NAME}-controller/etc/crio/crio.conf "${TMP_CRIO_CONF}"
  #sed -i 's/^\(#[[:space:]]*\)\?storage_driver[[:space:]]*=.*/storage_driver = "zfs"/' ${TMP_CRIO_CONF}

  ## rsync somehow ducks up
  # sysctl -w kernel.unprivileged_userns_clone=1
  # lxc-create -t oci -n a1 -- --dhcp -u docker://docker.io/${REGISTRY_PROXY_REPO}
  # lxc-start -n a1

  ## remove '^lxc.(init|execute)' from lxc container config
  ## might not be possible to migrate this to lxd
  # lxc-to-lxd --rsync-args '-zz' --containers a1
  # lxc delete -f a1

  registry_proxy_post::common ${TMP_CA}

  local REGISTRY_PROXY_ADDRESS="$(docker container inspect ${REGISTRY_PROXY_HOSTNAME} -f '{{.NetworkSettings.IPAddress}}')" TMP_SYSTEMD_SVC=$(mktemp)
  cat <<EOF >${TMP_SYSTEMD_SVC}
[Service]
Environment="HTTP_PROXY=http://${REGISTRY_PROXY_ADDRESS}:3128/"
Environment="HTTPS_PROXY=http://${REGISTRY_PROXY_ADDRESS}:3128/"
Environment="NO_PROXY=$(string_join , ${KUBE_NOPROXY_SETTING[@]})"
EOF

  for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-" | grep -Ev '.*-etcd$'); do
    lxc file push "${TMP_CA}" ${i}/etc/ssl/certs/ca-certificates.crt
    lxc file push "${TMP_SYSTEMD_SVC}" ${i}/etc/systemd/system/crio.service.d/registry-proxy.conf -p
    #lxc file push "${TMP_CRIO_CONF}" ${i}/etc/crio/crio.conf
    lxc exec ${i} -- /bin/sh -c 'systemctl daemon-reload && systemctl restart crio'
  done

  rm "${TMP_CA}" "${TMP_SYSTEMD_SVC}" "${TMP_CRIO_CONF}"
}

registry_proxy_post(){
  registry_proxy_post::${K8S_RUNTIME}
}

launch_cluster_post(){
  # PSP
  local ALLOW_ALL_PSP
  : ${ALLOW_ALL_PSP:=0}
  PRIVILEGED_PSP=99-privileged
  RESTRICTED_PSP=01-restricted
  [ ${ALLOW_ALL_PSP} -eq 0 ] && DEFAULT_PSP=${PRIVILEGED_PSP} || DEFAULT_PSP=${RESTRICTED_PSP}
  PRIVILEGED_PSP="${PRIVILEGED_PSP}" envsubst <${MYDIR}/manifests/priviledged-psp.yml.shtpl | kubectl apply -f-
  RESTRICTED_PSP="${RESTRICTED_PSP}" envsubst <${MYDIR}/manifests/restricted-psp.yml.shtpl | kubectl apply -f-
  DEFAULT_PSP="${DEFAULT_PSP}" envsubst <${MYDIR}/manifests/default-psp-crb.yml.shtpl | kubectl apply -f-

  [ ${INSTALL_REGISTRY_PROXY} -eq 0 ] && registry_proxy_post
}

check_zfs(){
  return
  [ -n "${ZFS_DATASET}" ] && [ "$(zfs get -Ho value overlay ${ZFS_DATASET})" != "on" ] \
    && echo "Please enable ZFS dataset overlay by running \"zfs set overlay=on ${ZFS_DATASET}\"." \
    && exit 1 ||:
}

launch_cluster::k3d(){
  [ ${INSTALL_STORAGE} -eq 0 ] && K3D_OPTS+=('--server-arg' '--disable=local-storage')
  [ ${INSTALL_SERVICE_MESH} -eq 0 ] && K3D_OPTS+=(
    '--server-arg' '--disable=traefik'
    '--server-arg' '--disable=servicelb'
  )

  # base containerd config
  cat <<EOF > ${CLUSTER_CONFIG_HOST_PATH}/config.toml.tmpl
# Original section: no changes
[plugins.opt]
path = "{{ .NodeConfig.Containerd.Opt }}"
[plugins.cri]
stream_server_address = "{{ .NodeConfig.AgentConfig.NodeName }}"
stream_server_port = "10010"
{{- if .IsRunningInUserNS }}
disable_cgroup = true
disable_apparmor = true
restrict_oom_score_adj = true
{{ end -}}
{{- if .NodeConfig.AgentConfig.PauseImage }}
sandbox_image = "{{ .NodeConfig.AgentConfig.PauseImage }}"
{{ end -}}
{{- if not .NodeConfig.NoFlannel }}
  [plugins.cri.cni]
    bin_dir = "{{ .NodeConfig.AgentConfig.CNIBinDir }}"
    conf_dir = "{{ .NodeConfig.AgentConfig.CNIConfDir }}"
{{ end -}}

[plugins.cri.containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.${SHIM_VERSION}"

#[plugins.cri.containerd.default_runtime]
#  #runtime_type = "io.containerd.runtime.v1.linux"
#  runtime_type = "io.containerd.runc.${SHIM_VERSION}"

[plugins.cri.registry.mirrors]
  [plugins.cri.registry.mirrors."${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}"]
    endpoint = ["http://${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}"]
# good for blocking out registries - non-pull-through registry endpoint for wildcard
#  [plugins.cri.registry.mirrors."*"]
#    endpoint = ["http://${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}"]
EOF

#  for i in $(seq 16 31); do
#    cat <<EOF >>${CLUSTER_CONFIG_HOST_PATH}/config.toml.tmpl
#  [plugins.cri.registry.mirrors."172.${i}.0.2:${HARBOR_HTTP_NODEPORT}"]
#    endpoint = ["http://172.${i}.0.2:${HARBOR_HTTP_NODEPORT}"]
#EOF
#  done
#
#  for i in $(seq 0 16 255); do
#    cat <<EOF >>${CLUSTER_CONFIG_HOST_PATH}/config.toml.tmpl
#  [plugins.cri.registry.mirrors."192.168.${i}.2:${HARBOR_HTTP_NODEPORT}"]
#    endpoint = ["http://192.168.${i}.2:${HARBOR_HTTP_NODEPORT}"]
#EOF
#  done

  [ "$(docker info -f '{{.Driver}}')" = "zfs" ] \
    && ZFS_DATASET="$(docker info -f '{{range $a := .DriverStatus}}{{if eq (index $a 0) "Parent Dataset"}}{{(index $a 1)}}{{end}}{{end}}')" \
    && check_zfs && create_volumes ||:

  echo "${DOCKER_ROOT_FS}" | grep -E '^(btr|tmp)fs$' && create_volumes ||:

  K3D_OPTS+=($(printf "%s\n" "${K3D_LIB_MOUNTS_ALL[@]}" | sort -u))
  # enable RuntimeClass admission controller?: https://kubernetes.io/docs/concepts/containers/runtime-class/
  k3d c -t 0 \
    -n ${CLUSTER_NAME} \
    -w ${NUM_WORKERS} \
    -a $((6443+${RANDOM}%100)) \
    --agent-arg '--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%' \
    --agent-arg '--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%' \
    --server-arg '--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%' \
    --server-arg '--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%' \
    --server-arg '--kube-apiserver-arg=enable-admission-plugins=PodSecurityPolicy,NodeRestriction' \
    -i rancher/k3s:v${RUNTIME_VERSIONS[k3d]} \
    -v ${CLUSTER_CONFIG_HOST_PATH}/config.toml.tmpl:/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl \
    ${K3D_OPTS[@]}
  export KUBECONFIG=$(k3d get-kubeconfig -n ${CLUSTER_NAME})
  launch_cluster_post

  echo "Waiting for k3s cluster to come up…"
  until kubectl wait --for condition=ready node k3d-${CLUSTER_NAME}-server; do sleep 1; done 2>/dev/null
  for i in $(seq ${NUM_WORKERS}); do
    until kubectl wait --for condition=ready node k3d-${CLUSTER_NAME}-worker-$((${i}-1)); do sleep 1; done 2>/dev/null
  done

  [ ${OLD_K3S} -eq 0 ] || until kubectl -n kube-system wait --for condition=available deploy metrics-server; do sleep 1; done 2>/dev/null
}

launch_cluster::kubedee(){
  local LXD_STORAGE_POOL="kubedee"

  [ "$(lxc storage show ${LXD_STORAGE_POOL} | awk '/^driver:\s+/ {print $NF}')" = "zfs" ] \
    && ZFS_DATASET="$(lxc storage get ${LXD_STORAGE_POOL} zfs.pool_name)" && check_zfs

  # crio.conf `storage_driver` value might need parameterization
  # ref: https://github.com/containers/storage/blob/master/docs/containers-storage.conf.5.md#storage-table
  "${MYDIR}/kubedee/kubedee" --kubernetes-version v${RUNTIME_VERSIONS[kubedee]} --num-worker ${NUM_WORKERS} ${KUBEDEE_OPTS[@]} up ${CLUSTER_NAME}
  launch_cluster_post
}

launch_cluster(){
  [ ${K8S_RUNTIME} = "k3d" ] && mkdir -p ${CLUSTER_CONFIG_HOST_PATH}/ssl
  [ ${INSTALL_LOCAL_REGISTRY:=1} -eq 0 ] && K3D_OPTS+=(
    '--registry-name' "${LOCAL_REGISTRY_HOST:=registry.local}"
    '--registry-port' "${LOCAL_REGISTRY_PORT:=5000}"
    '--enable-registry'
    #'--registry-volume' 'k3d-registry' '--enable-registry-cache'
  ) && KUBEDEE_OPTS+=('--enable-insecure-registry') \
  && KUBE_NOPROXY_SETTING+=("${LOCAL_REGISTRY_HOST}") ||:

  [ ${INSTALL_KATA} -eq 0 ] && kata_pre
  [ ${INSTALL_REGISTRY_PROXY} -eq 0 ] && registry_proxy_pre

  launch_cluster::${K8S_RUNTIME}

  # Kata-post
  [ ${INSTALL_KATA} -eq 0 ] && kubectl apply -f "${MYDIR}/manifests/kata-runtime-classes.yml" \
    && [ "${K8S_RUNTIME}" = "k3d" ] \
    && kubectl apply -f "${MYDIR}/manifests/k3d-syslogd.yml" \
    && until kubectl -n kube-system wait --for condition=ready pod -l app=syslog; do sleep 1; done 2>/dev/null ||:
}

teardown_cluster::k3d(){
  k3d d --prune -n ${CLUSTER_NAME} ||:
  rm -rf ${CLUSTER_CONFIG_HOST_PATH} ||:
  echo "${DOCKER_ROOT_FS}" | grep -E '^(btr|tmp)fs$' || [ "$(docker info -f '{{.Driver}}')" = "zfs" ] && docker volume rm -f $(docker volume ls --format '{{.Name}}' | awk "/^${K8S_RUNTIME}-${CLUSTER_NAME}-/") &>/dev/null ||:
}

teardown_cluster::kubedee(){
  "${MYDIR}/kubedee/kubedee" delete ${CLUSTER_NAME} ||:
}

install_dashboard(){
  # https://www.artificialworlds.net/blog/2012/10/17/bash-associative-array-examples/
  declare -A K8S_DASHBOARD=(
    [v1.18]="v2.0.0"
    [v1.17]="v2.0.0-rc7"
    [v1.16]="v2.0.0-rc3"
    [v1.15]="v2.0.0-beta4"
    [v1.14]="v2.0.0-beta1"
  )
  echo "Installing Dashboard…"
  local KUBELET_VERSION="$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}' | awk -F- '{print $1}')"

  [ ${K8S_DASHBOARD[${KUBELET_VERSION%.*}]+_} ] \
    && curl -sSL https://raw.githubusercontent.com/kubernetes/dashboard/${K8S_DASHBOARD[${KUBELET_VERSION%.*}]}/aio/deploy/alternative.yaml | sed \
      -e '/enable-insecure-login/d' | kubectl apply -f- \
    || (echo "Unsupported Kubelet version ${KUBELET_VERSION%.*}. No dashboard will be installed." && exit 0)
  
  kubectl apply -f "${MYDIR}/manifests/k8s-dashboard-cr.yml"
}

# we could be installing through K3S' `helm.cattle.io/v1` API (like in github.com/mrchrd/k3s-quickstart), but we shouldn't be making such assumptions
setup_helm(){
  declare -A HELM_PLUGINS=(
    ['https://github.com/hypnoglow/helm-s3']="v0.9.2"
    ['https://github.com/zendesk/helm-secrets']="v2.0.2"
    ['https://github.com/aslafy-z/helm-git']="v0.7.0"
  )
  helm version --template '{{.Version}}' | grep -E '^v3\.' || TILLER_SERVICE_ACCOUNT="tiller"
  # Helm v2: `helm version -c --template '{{.Client.SemVer}}'`
  if [ -z "${TILLER_SERVICE_ACCOUNT}" ]; then  # helm3
    HELM_PLUGINS['https://github.com/databus23/helm-diff']="v3.1.1"
    HELM_PLUGINS['https://github.com/hayorov/helm-gcs']="0.3.1"
  else  # helm2
    HELM_PLUGINS['https://github.com/databus23/helm-diff']="v2.11.0+5"
    HELM_PLUGINS['https://github.com/hayorov/helm-gcs']="0.2.2"
    HELM_PLUGINS['https://github.com/rimusz/helm-tiller']="v0.9.3"
  fi

  [ -n "${TILLER_SERVICE_ACCOUNT}" ] && install_tiller

  echo "Installing Helm plugins…"
  for i in "${!HELM_PLUGINS[@]}"; do helm plugin install ${i} --version ${HELM_PLUGINS[${i}]} ||:; done
}

install_tiller(){
  echo "Installing Tiller…"
  TILLER_SERVICE_ACCOUNT="${TILLER_SERVICE_ACCOUNT}" envsubst <${MYDIR}/manifests/tiller-cluster-admin.yml.shtpl | kubectl apply -f-

  helm init --upgrade --service-account ${TILLER_SERVICE_ACCOUNT}
  until kubectl -n kube-system wait --for condition=available deploy tiller-deploy; do sleep 1; done 2>/dev/null
}

install_service_mesh(){
  kubectl get ns ${NAMESPACES_NETWORK} &>/dev/null || kubectl create ns ${NAMESPACES_NETWORK}
  echo "Installing Istio Resources…"

  # secure Citadel Node Agent's SDS unix socket
  NAMESPACES_NETWORK="${NAMESPACES_NETWORK}" envsubst <${MYDIR}/manifests/istio-psp.yml.shtpl | kubectl apply -f-

  # be sure to prefix configuration configuration keys with `values.` when using `istioctl`
  #istioctl manifest apply --wait \
  #  --set values.global.proxy.accessLogFile="/dev/stdout"

  # Disables Citadel's SA secret generation for the namespace (unless `security.enableNamespacesByDefault` is already `false` and therefore opt-in)
  #kubectl label ns default ca.istio.io/override=false

  HELMFILE_ARGS+=(
    '-l' "name=${RELEASES_ISTIO_INIT:=istio-init}"
    '-l' "name=${RELEASES_ISTIO:=istio}"
    '-l' "name=${RELEASES_JAEGER_OPERATOR:=jaeger-operator}"
    '-l' "name=${RELEASES_ISTIO_BASE:=istio-base}"
    '-l' "name=${RELEASES_ISTIO_CONTROL:=istio-control}"
    '-l' "name=${RELEASES_ISTIO_GATEWAY_EGRESS:=istio-egress}"
    '-l' "name=${RELEASES_ISTIO_GATEWAY_INGRESS:=istio-ingress}"
    '-l' "name=${RELEASES_ISTIO_POLICY:=istio-policy}"
    '-l' "name=${RELEASES_ISTIO_TELEMETRY_KIALI:=istio-kiali}"
    '-l' "name=${RELEASES_ISTIO_TELEMETRY_PROMETHEUS_OPERATOR:=istio-prometheus-operator}"
    '-l' "name=${RELEASES_ISTIO_TELEMETRY_TRACING:=istio-tracing}"
  )
}

install_minio(){
  echo "Installing MinIO…"

  : ${MINIO_ACCESS_KEY:=AKIAIOSFODNN7EXAMPLE}
  : ${MINIO_SECRET_KEY:="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
  : ${MINIO_DEFAULT_BUCKET:=minio-bucket}
  : ${MINIO_SVC_PORT:=9000}

  HELMFILE_ARGS+=('-l' "name=${RELEASES_MINIO:=minio}")
}

install_minio_client(){
  local MC_NAME="mc-${RANDOM}"
  NAMESPACES_STORAGE="${NAMESPACES_STORAGE}" MC_NAME="${MC_NAME}" envsubst <${MYDIR}/manifests/minio-client-deploy.yml.shtpl | kubectl apply -f-

  until kubectl -n ${NAMESPACES_STORAGE} wait --for condition=available deploy ${MC_NAME}; do sleep 1; done 2>/dev/null
  kubectl -n ${NAMESPACES_STORAGE} exec $(kubectl -n ${NAMESPACES_STORAGE} get pods -o jsonpath="{.items[?(@.metadata.labels.app==\"${MC_NAME}\")].metadata.name}" | awk '{print $1}') -- /bin/sh -xc "mc config host add minio http://${RELEASES_MINIO}.${NAMESPACES_STORAGE}.svc:${MINIO_SVC_PORT} ${MINIO_ACCESS_KEY} ${MINIO_SECRET_KEY}"

  echo "MinIO is available under http://${RELEASES_MINIO}.${NAMESPACES_STORAGE}.svc:${MINIO_SVC_PORT} with access key \"${MINIO_ACCESS_KEY}\", secret key \"${MINIO_SECRET_KEY}\" and default bucket \"${MINIO_DEFAULT_BUCKET}\"."
}

install_openebs(){
  echo "Installing OpenEBS…"
  local NODE_NAME
  OPENEBS_OMIT_LOOPDEVS="$(string_join , $(losetup -nlO NAME))"

  [ "${K8S_RUNTIME}" = "k3d" ] && for i in $(seq 0 ${NUM_WORKERS}); do
    [ ${i} -eq 0 ] && NODE_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-server" || NODE_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-worker-$((${i}-1))"
    docker exec ${NODE_NAME} mkdir -p /run/udev
  done

  # set OpenEBS-based HostPath as default storage class
  for i in $(kubectl get sc -o jsonpath='{.items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")].metadata.name}'); do
    kubectl annotate sc ${i} storageclass.kubernetes.io/is-default-class-
  done

  kubectl apply -f "${MYDIR}/manifests/openebs-storage-classes.yml"
  HELMFILE_ARGS+=('-l' "name=${RELEASES_OPENEBS:=openebs}")
}

install_prometheus_operator(){
  echo "Installing Prometheus Operator…"
  local RELEASES_PROMETHEUS_OPERATOR=${RELEASES_PROMETHEUS_OPERATOR:=prometheus-operator}
  : ${THANOS_OBJSTORE_CONFIG_SECRET:=thanos-objstore-config}

  # has to be object-store.yaml due to hard-coding of the filename in banzaicloud/thanos chart's secret.yaml template
  : ${THANOS_OBJSTORE_CONFIG_FILENAME:=object-store.yaml}

  NAMESPACES_MONITORING="${NAMESPACES_MONITORING}" \
  NAMESPACES_STORAGE="${NAMESPACES_STORAGE}" \
  THANOS_OBJSTORE_CONFIG_SECRET="${THANOS_OBJSTORE_CONFIG_SECRET}" \
  THANOS_OBJSTORE_CONFIG_FILENAME="${THANOS_OBJSTORE_CONFIG_FILENAME}" \
  RELEASES_MINIO="${RELEASES_MINIO}" \
  MINIO_DEFAULT_BUCKET="${MINIO_DEFAULT_BUCKET}" \
  MINIO_SVC_PORT="${MINIO_SVC_PORT}" \
  MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY}" \
  MINIO_SECRET_KEY="${MINIO_SECRET_KEY}" \
  envsubst <${MYDIR}/manifests/thanos-objstore-secret.yml.shtpl | kubectl apply -f-

  NAMESPACES_MONITORING="${NAMESPACES_MONITORING}" \
  RELEASES_PROMETHEUS_OPERATOR="${RELEASES_PROMETHEUS_OPERATOR}" \
  envsubst <${MYDIR}/manifests/thanos-prometheus-query-svc.yml.shtpl | kubectl apply -f-

  HELMFILE_ARGS+=(
    '-l' "name=${RELEASES_THANOS:=thanos}"
    '-l' "name=${RELEASES_PROMETHEUS_OPERATOR}"
    '-l' "name=${RELEASES_PROMETHEUS_ADAPTER:=prometheus-adapter}"
  )
}

install_storage(){
  kubectl create secret docker-registry local-harbor --docker-username=admin --docker-password=${HARBOR_ADMIN_PASSWORD:=Harbor12345}
  install_openebs && install_minio && HELMFILE_ARGS+=(
    '-l' "name=${RELEASES_HARBOR:=harbor}"
    '-l' "name=${RELEASES_PATRONI:=patroni}"
    '-l' "name=${RELEASES_REDIS:=redis}"
  ) ||:
}

install_monitoring(){
  kubectl get ns ${NAMESPACES_MONITORING} &>/dev/null || kubectl create ns ${NAMESPACES_MONITORING}
  install_prometheus_operator && [ ${INSTALL_SERVICE_MESH} -eq 0 ] && HELMFILE_ARGS+=(
    '-l' "name=${RELEASES_ISTIO_PROMETHEUS_OPERATOR:=istio-prometheus-operator}"
  ) ||:
}

install_serverless(){
  # kubeless/knative/openfaas?
  HELMFILE_ARGS+=('-l' "name=${RELEASES_KUBELESS:=kubeless}")
}

show_ingress_points::k3d(){
  local NODE_NAME
  for i in $(seq 0 ${NUM_WORKERS}); do
    [ ${i} -eq 0 ] && NODE_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-server" || NODE_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-worker-$((${i}-1))"
    docker container inspect ${NODE_NAME} -f "{{(index .NetworkSettings.Networks \"${K8S_RUNTIME}-${CLUSTER_NAME}\").IPAddress}}"
  done
}

show_ingress_points::kubedee(){
  lxc list -cn4 --format csv | awk '/-controller,/ {print $1}' | awk -F, '{print $NF}'
  lxc list -cn4 --format csv | awk '/-worker-/ {print $1}' | awk -F, '{print $NF}'
}

show_ingress_points(){
  echo "Worker node IP addresses:"
  show_ingress_points::${K8S_RUNTIME}
  #kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}'  #|| kubectl -n kube-system get svc/traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
}

kube_up(){
  launch_cluster
  install_dashboard
  setup_helm

  local i
  for i in ${!RELEASES[@]}; do export RELEASES_${i^^}="${RELEASES[${i}]}"; done
  for i in ${!NAMESPACES[@]}; do export NAMESPACES_${i^^}="${NAMESPACES[${i}]}"; done
  for i in ${!VERSIONS[@]}; do export VERSIONS_${i^^}="${VERSIONS[${i}]}"; done

  [ ${INSTALL_STORAGE} -eq 0 ] && install_storage
  [ ${INSTALL_SERVICE_MESH} -eq 0 ] && install_service_mesh
  [ ${INSTALL_MONITORING} -eq 0 ] && install_monitoring
  [ ${INSTALL_SERVERLESS} -eq 0 ] && install_serverless

  # apply helm releases
  helmfile --no-color --allow-no-matching-release -f "${MYDIR}/helmfile.yaml" ${HELMFILE_ARGS[@]} sync

  [ ${INSTALL_STORAGE} -eq 0 ] && install_minio_client
  [ ${INSTALL_SERVICE_MESH} -eq 0 ] && [ ${ISTIO_SIDECAR_AUTOINJECT:=0} -eq 0 ] && echo "Marking the default namespace for Envoy injection…" && kubectl label ns default istio-injection=enabled ||:
    #&& kubectl apply -f "${MYDIR}/manifests/selfsigned-certmanager.yml" ||:

  show_ingress_points
  echo "Now run \"kubectl proxy\" and go to http://127.0.0.1:8001/api/v1/namespaces/kubernetes-dashboard/services/http%3Akubernetes-dashboard%3A/proxy/ for your K8S dashboard."
}

kube_down(){
  [ ${INSTALL_REGISTRY_PROXY} -eq 0 ] && docker rm -fv "${REGISTRY_PROXY_HOSTNAME}" ||:
  teardown_cluster::${K8S_RUNTIME}
}

declare -A SCRIPT_OPS=(
  [up]="kube_up"
  [down]="kube_down"
)

print_usage(){
  local MYNAME="$(basename ${0})"
  cat >&2 <<EOF
${MYNAME%.*} - Linux-centric scaffold for K8S development

Usage: ${0} [options] <up|down>

Options:
  --no-*, --with-*                    disable/enable installation of selected
                                      component (choice from: kata,
                                        registry-proxy, monitoring, serverless,
                                        service-mesh, storage, local-registry)
                                      (env: non-zero value on INSTALL_*)
  -N <name>, --name <name>            cluster name
                                      (default: k3s-default, env: CLUSTER_NAME)
  -n <num>, --num <num>               number of workers
                                      (default: nproc/4, env: NUM_WORKERS)
  -r <runtime>, --runtime <runtime>   runtime choice
                                      (default: k3d, env: K8S_RUNTIME)
                                      (choice of: k3d, kubedee)
  -t <tag>, --tag <tag>               runtime version (env: RUNTIME_TAG)

Environment variables:

  Registry proxy (ref: https://github.com/rpardini/docker-registry-proxy#usage ):
    PROXY_REGISTRIES    space-delimited string listing registry domains to cache
                        OCI image layers from
    AUTH_REGISTRIES     space-delimited string listing "domain:username:password"
                        information for the proxy to authenticate to registries
EOF
  exit 1
}

main(){
  : ${INSTALL_KATA:=0}
  : ${INSTALL_REGISTRY_PROXY:=0}

  : ${INSTALL_STORAGE:=0}
  : ${INSTALL_SERVICE_MESH:=0}
  : ${INSTALL_MONITORING:=0}
  : ${INSTALL_SERVERLESS:=0}

  : ${K8S_RUNTIME:=k3d}
  : ${CLUSTER_NAME:=k3s-default}
  : ${NUM_WORKERS:=${DEFAULT_WORKERS}}

  while [ ${#} -gt 0 ]; do
    case "${1}" in
      --no-*)
        COMPONENT=${1/--no-/}
        COMPONENT=${COMPONENT//-/_}
        declare INSTALL_${COMPONENT^^}=1
        shift
        ;;
      --with-*)
        COMPONENT=${1/--with-/}
        COMPONENT=${COMPONENT//-/_}
        declare INSTALL_${COMPONENT^^}=0
        shift
        ;;
      -N | --name)
        CLUSTER_NAME="${2}"
        shift 2
        ;;
      -n | --num)
        case "${2}" in
          ''|*[!0-9]*)
            echo "Malformed number of workers."
            exit 1
            ;;
          *) ;;
        esac
        NUM_WORKERS="${2}"
        shift 2
        ;;
      -r | --runtime)
        K8S_RUNTIME="${2}"
        case "${2}" in
          k3d | kubedee) ;;
          *)
            echo "Unexpected runtime provided"
            exit 1
            ;;
        esac
        shift 2
        ;;
      -t | --tag)
        RUNTIME_TAG="${2}"
        shift 2
        ;;
      up | down)
        SCRIPT_OP="${1}"
        shift
        ;;
      *)
        print_usage
        ;;
    esac
  done

  [ -z "${SCRIPT_OP}" ] && print_usage

  declare -A NAMESPACES=(
    [monitoring]="${NAMESPACES_MONITORING:=monitoring}"
    [network]="${NAMESPACES_NETWORK:=network}"
    [serverless]="${NAMESPACES_SERVERLESS:=serverless}"
    [serverless_functions]="${NAMESPACES_SERVERLESS_FUNCTIONS:=serverless-functions}"
    [storage]="${NAMESPACES_STORAGE:=storage}"
  )

  # harbor
  : ${HARBOR_CORE_HOSTNAME:=core.harbor.domain}
  : ${HARBOR_HTTP_NODEPORT:=30002}
  : ${DOCKER_VOLUME_PLUGIN:=ashald/docker-volume-loopback}

  declare -A RUNTIME_VERSIONS=(
    #[k3d]="0.9.1"  # k8s-1.15
    #[k3d]="1.0.1"  # k8s-1.16
    [k3d]="${RUNTIME_TAG:-1.18.2-k3s1}"
    [kubedee]="${RUNTIME_TAG:-1.18.3}"
  )
  echo "${RUNTIME_VERSIONS[k3d]}" | grep -E '^0\.[0-9]\.' && OLD_K3S=0 || OLD_K3S=1
  [ ${OLD_K3S} -eq 0 ] && SHIM_VERSION=v1 || SHIM_VERSION=v2

  : ${CLUSTER_CONFIG_HOST_PATH:=/var/tmp/k3s/${CLUSTER_NAME}}

  # registry proxy config
  : ${REGISTRY_PROXY_REPO:="rpardini/docker-registry-proxy:0.3.0"}
  REGISTRY_PROXY_DOCKER_ARGS=()
  : ${REGISTRY_PROXY_HOSTNAME:="${K8S_RUNTIME}-${CLUSTER_NAME}-registry-proxy-cache.local"}
  : ${REGISTRY_PROXY_HOST_PATH:=/var/tmp/oci-registry}
  mkdir -p "${REGISTRY_PROXY_HOST_PATH}"

  # in k3d, the controller node is also a worker, also need to figure out docker as a k3d-specific dep (schu/kubedee#62)
  [ "${K8S_RUNTIME}" = "k3d" ] && NUM_WORKERS="$((${NUM_WORKERS}-1))" && BINARY_DEPENDENCIES+=(k3d) || BINARY_DEPENDENCIES+=(kubedee lxc cfssl jq)

  # dep check
  for i in ${BINARY_DEPENDENCIES[@]}; do
    type -p ${i} &>/dev/null || (echo "Missing binary \"${i}\" in PATH, exiting." && exit 1)
  done

  ${SCRIPT_OPS[${SCRIPT_OP}]}
}

main "${@}"
