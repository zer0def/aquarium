#!/bin/bash -e
if [ -n "${SCRIPT_DEBUG}" ]; then
  set -x
  export KUBEDEE_DEBUG=1
fi
export MYDIR="$(dirname "$(readlink -f "${0}")")"
. "${MYDIR}/common"

# inb4 someone comes out yelling they don't have coreutils installed
BINARY_DEPENDENCIES=(docker "${HELM_BIN}" helmfile kubectl)

# currently installed resources' requests have a hard time fitting on sub-quad-thread machines
DEFAULT_WORKERS="$((4/$(nproc)))"
[ "${DEFAULT_WORKERS}" -ge 2 ] || DEFAULT_WORKERS=2

K3D_OPTS=()
KUBEDEE_OPTS=()
RESTART_CRIO=1

install_docker_volume_plugin(){
  local PLUGIN_LS_OUT="$(docker plugin ls --format '{{.Name}},{{.Enabled}}' | grep -E "^${DOCKER_VOLUME_PLUGIN}")"
  [ -n "${PLUGIN_LS_OUT}" ] || docker plugin install "${DOCKER_VOLUME_PLUGIN}" DATA_DIR="${DOCKER_VOLUME_DIR:=/tmp/docker-loop/data}"
  echo "Sleeping 3 seconds for docker-volume-loopback to launch…" && sleep 3
  [ "${PLUGIN_LS_OUT##*,}" = "true" ] || docker plugin enable "${DOCKER_VOLUME_PLUGIN}"
}

create_volumes(){
  local DOCKER_VOLUME_DRIVER
  : ${DOCKER_VOLUME_DRIVER:=${DOCKER_VOLUME_PLUGIN:-local}}
  [ -z "${DOCKER_VOLUME_PLUGIN}" ] || install_docker_volume_plugin
  local VOLUME_NAME
  for i in $(seq 0 "$((${NUM_WORKERS}-1))"); do
    #[ "${i}" -eq 0 ] && VOLUME_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-server-0" || VOLUME_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-agent-$((${i}-1))"
    VOLUME_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-server-${i}"
    docker volume create -d "${DOCKER_VOLUME_DRIVER}" "${VOLUME_NAME}" -o sparse=true -o fs=ext4 -o size=20GiB &>/dev/null
    K3D_OPTS+=('-v' "${VOLUME_NAME}:/var/lib/rancher/k3s@${VOLUME_NAME}")
    if [ "${OLD_K3S}" -ne 0 ]; then
      docker volume create \
        -d "${DOCKER_VOLUME_DRIVER}" \
        -o sparse=true \
        -o fs=ext4 \
        -o size=10GiB \
        "${VOLUME_NAME}-kubelet" &>/dev/null
      K3D_OPTS+=('-v' "${VOLUME_NAME}-kubelet:/var/lib/kubelet@${VOLUME_NAME}")
    fi
  done
}

urlparse(){
  local protocol="${1%%://*}" tail="${1#*://}"
  [ "${protocol}" != "${tail}" ] || unset protocol
  local head="${tail%%#*}" fragment="${tail#*#}"
  [ "${fragment}" != "${head}" ] || unset fragment
  local head="${head%%\?*}" qs="${head#*\?}"
  [ "${qs}" != "${head}" ] || unset qs
  local netloc="${head%%/*}" path="${head#*/}"
  [ "${netloc}" != "${path}" ] || unset path
  local auth="${netloc%@*}" endpoint="${netloc#*@}"
  [ "${auth}" != "${endpoint}" ] || unset auth
  local user pass
  [ -z "${auth}" ] || user="${auth%%:*}" pass="${auth#*:}"
  local host="${endpoint%:*}" port="${endpoint##*:}"
  [ "${port}" != "${host}" ] || unset port
  echo "${protocol}|${user}|${pass}|${host}|${port}|${path}|${qs}|${fragment}"
}

# common functions start
registry_proxy_pre::k3d(){
  #for i in $(seq 0 $((${NUM_CONTROLLERS:-1}-1))); do KUBE_NOPROXY_SETTING+=(); done && \
  for i in $(seq 0 $((${NUM_WORKERS}-1))); do KUBE_NOPROXY_SETTING+=("k3d-${CLUSTER_NAME}-agent-${i}" "k3d-${CLUSTER_NAME}-server-${i}"); done \
  && mkdir -p "${REGISTRY_PROXY_HOST_PATH}" \
  && docker run --entrypoint '' --rm "rancher/k3s:v${RUNTIME_VERSIONS[k3d]}" cat /etc/ssl/certs/ca-certificates.crt > "${CLUSTER_CONFIG_HOST_PATH}/ssl/ca-certificates.crt" \
  && K3D_OPTS+=(
    '-e' "HTTP_PROXY=http://${REGISTRY_PROXY_HOSTNAME}:3128@servers:*"    '-e' "HTTP_PROXY=http://${REGISTRY_PROXY_HOSTNAME}:3128@agents:*"
    '-e' "HTTPS_PROXY=http://${REGISTRY_PROXY_HOSTNAME}:3128@servers:*"   '-e' "HTTPS_PROXY=http://${REGISTRY_PROXY_HOSTNAME}:3128@agents:*"
    '-e' "NO_PROXY=$(string_join , ${KUBE_NOPROXY_SETTING[@]})@servers:*" '-e' "NO_PROXY=$(string_join , ${KUBE_NOPROXY_SETTING[@]})@agents:*"
    '-v' "${CLUSTER_CONFIG_HOST_PATH}/ssl:/etc/ssl/certs"
  )
}

registry_proxy_pre::kubedee(){
  :
}

registry_proxy_pre(){
  "registry_proxy_pre::${K8S_RUNTIME}"
}

registry_proxy_post::k3d(){
  # arguably common part start
  REGISTRY_PROXY_DOCKER_ARGS+=('--network' "k3d-${CLUSTER_NAME}")
  registry_proxy_post::shared "${CLUSTER_CONFIG_HOST_PATH}/ssl/ca-certificates.crt"
  # arguably common part end
}

registry_proxy_post(){
  "registry_proxy_post::${K8S_RUNTIME}"
}

launch_cluster_post(){
  [ "${INSTALL_REGISTRY_PROXY}" -ne 0 ] || registry_proxy_post
}

check_zfs(){
  return
  [ -n "${ZFS_DATASET}" ] && [ "$(zfs get -Ho value overlay "${ZFS_DATASET}")" != "on" ] \
    && echo "Please enable ZFS dataset overlay by running \"zfs set overlay=on ${ZFS_DATASET}\"." \
    && exit 1 ||:
}

launch_cluster::k3d(){
  #[ "${INSTALL_STORAGE}" -eq 0 ] && K3D_OPTS+=('--k3s-server-arg' '--disable=local-storage')
  [ "${INSTALL_SERVICE_MESH}" -ne 0 ] || K3D_OPTS+=('--no-lb'
    '--k3s-arg' '--disable=traefik@servers:*'
    '--k3s-arg' '--disable=servicelb@servers:*'
  )

  # base containerd config
  cat <<EOF > "${CLUSTER_CONFIG_HOST_PATH}/config.toml.tmpl"
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
  privileged_without_host_devices = false
  runtime_type = "io.containerd.runc.${SHIM_VERSION}"

[plugins.cri.containerd.runtimes.kata-qemu]
  privileged_without_host_devices = true
  runtime_type = "io.containerd.kata.v2"
  pod_annotations = ["io.katacontainers.*"]
  container_annotations = ["io.katacontainers.*"]
[plugins.cri.containerd.runtimes.kata-qemu.options]
  ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml"
[plugins.cri.containerd.runtimes.kata-fc]
  privileged_without_host_devices = true
  runtime_type = "io.containerd.kata.v2"
  pod_annotations = ["io.katacontainers.*"]
  container_annotations = ["io.katacontainers.*"]
[plugins.cri.containerd.runtimes.kata-fc.options]
  ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-fc.toml"
[plugins.cri.containerd.runtimes.kata-clh]
  privileged_without_host_devices = true
  runtime_type = "io.containerd.kata.v2"
  pod_annotations = ["io.katacontainers.*"]
  container_annotations = ["io.katacontainers.*"]
[plugins.cri.containerd.runtimes.kata-clh.options]
  ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-clh.toml"

[plugins.cri.registry.mirrors]
  [plugins.cri.registry.mirrors."${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}"]
    endpoint = ["http://${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}"]
# good for blocking out registries - non-pull-through registry endpoint for wildcard
#  [plugins.cri.registry.mirrors."*"]
#    endpoint = ["http://${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}"]
EOF

  [ "$(docker info -f '{{.Driver}}')" = "zfs" ] \
    && ZFS_DATASET="$(docker info -f '{{range $a := .DriverStatus}}{{if eq (index $a 0) "Parent Dataset"}}{{(index $a 1)}}{{end}}{{end}}')" \
    && check_zfs && create_volumes ||:

  echo "${DOCKER_ROOT_FS}" | grep -vE '^(btr|tmp)fs$' || create_volumes

  # enable RuntimeClass admission controller?: https://kubernetes.io/docs/concepts/containers/runtime-class/
    #-v "/opt/kata:/opt/kata" \
    #-e "LD_LIBRARY_PATH=/lib64:/lib@servers:*" -e "LD_LIBRARY_PATH=/lib64:/lib@agents:*" \
    #-v "/usr/lib/libpthread.so.0:/lib/libpthread.so.0" -v "/usr/lib/libdl.so.2:/lib/libdl.so.2" \
    #-v "/usr/lib/libc.so.6:/lib/libc.so.6" -v "/usr/lib64/ld-linux-x86-64.so.2:/lib64/ld-linux-x86-64.so.2" \
  k3d cluster create "${CLUSTER_NAME}" --wait -s "${NUM_WORKERS}" -a 0 \
    -i "rancher/k3s:v${RUNTIME_VERSIONS[k3d]}" --api-port "$((6443+${RANDOM}%100))" \
    --k3s-arg '--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%@agents:*' \
    --k3s-arg '--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%@agents:*' \
    --k3s-arg '--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%@servers:*' \
    --k3s-arg '--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%@servers:*' \
    -v "${CLUSTER_CONFIG_HOST_PATH}/config.toml.tmpl:/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl" \
    ${K3D_OPTS[@]}
  export KUBECONFIG="$(k3d kubeconfig write "${CLUSTER_NAME}")" NODEPORT_HOST="$(docker inspect k3d-k3s-default-server-0 | jq -r .[].NetworkSettings.Networks[\"k3d-${CLUSTER_NAME}\"].IPAddress)"
  launch_cluster_post

  echo "Waiting for k3s cluster to come up…"
  until kubectl wait --for condition=ready node "${K8S_RUNTIME}-${CLUSTER_NAME}-server-0"; do sleep 1; done 2>/dev/null
  for i in $(seq 0 "$((${NUM_WORKERS}-1))"); do
    NODE_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-server-${i}"
    #if [ "${INSTALL_KATA}" -eq 0 ]; then
    #  docker exec "${NODE_NAME}" /bin/sh -c 'mkdir -p /run/kata-containers/shared/sandboxes; mount --bind --make-rshared /run/kata-containers/shared/sandboxes /run/kata-containers/shared/sandboxes'
    #fi

    until kubectl wait --for condition=ready node "${NODE_NAME}"; do sleep 1; done 2>/dev/null
  done

  [ "${OLD_K3S}" -eq 0 ] || until kubectl -n kube-system wait --for condition=available deploy metrics-server; do sleep 1; done 2>/dev/null
}

launch_cluster::kubedee(){
  local TMP_CRIO_CONF="$(mktemp)"

  [ "$(lxc storage show "${LXD_STORAGE_POOL}" | awk '/^driver:\s+/ {print $NF}')" = "zfs" ] \
    && ZFS_DATASET="$(lxc storage get "${LXD_STORAGE_POOL}" zfs.pool_name)" && check_zfs

  # crio.conf `storage_driver` value might need parameterization
  # ref: https://github.com/containers/storage/blob/master/docs/containers-storage.conf.5.md#storage-table
  HTTP_PROXY="http://${REGISTRY_PROXY_HOSTNAME}:3128" \
  HTTPS_PROXY="http://${REGISTRY_PROXY_HOSTNAME}:3128" \
  NO_PROXY="$(string_join , ${KUBE_NOPROXY_SETTING[@]})" \
  "${MYDIR}/kubedee/kubedee" --enable-kata \
    --apiserver-extra-hostnames "kubernetes.default,kubernetes.default.svc,kubernetes.default.svc.cluster.local" \
    --kubernetes-version "v${RUNTIME_VERSIONS[kubedee]}" \
    --num-worker "${NUM_WORKERS}" \
    --storage-pool "${LXD_STORAGE_POOL}" \
    ${KUBEDEE_OPTS[@]} up "${CLUSTER_NAME}"
  $("${MYDIR}/kubedee/kubedee" kubectl-env "${CLUSTER_NAME}")
  export NODEPORT_HOST="$(lxc list --format json | jq -r ".[]|select(.name==\"kubedee-${CLUSTER_NAME}-controller\").state.network.eth0.addresses[] | select(.family==\"inet\" and .scope==\"global\").address" | head -n1)"

  launch_cluster_post

  until kubectl -n kube-system wait --for condition=ready pod -l app=flannel,tier=node; do sleep 1; done 2>/dev/null
  until kubectl -n kube-system wait --for condition=ready pod -l k8s-app=kube-dns; do sleep 1; done 2>/dev/null

  for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-" | grep -Ev '.*-etcd$'); do
    #RUNTIMES_ROOT=/opt/kata envsubst <"${MYDIR}/utils/manifests/crio-runtime-override.conf.tpl" >"${TMP_CRIO_CONF}"
    #lxc file push -p "${TMP_CRIO_CONF}" "${i}/etc/crio/crio.conf.d/00-runtimes.conf"

    # might want to do this more persistently
    lxc exec "${i}" -- /bin/sh -c 'mkdir -p /run/kata-containers/shared/sandboxes; mount --bind --make-rshared /run/kata-containers/shared/sandboxes /run/kata-containers/shared/sandboxes'
    RESTART_CRIO=0
  done

  [ "${RESTART_CRIO}" -eq 0 ] && for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-" | grep -Ev '.*-(etcd|registry)$'); do
    lxc exec "${i}" -- /bin/sh -c 'systemctl daemon-reload; systemctl restart crio'
  done
  rm "${TMP_CRIO_CONF}"
}

launch_cluster(){
  if [ "${K8S_RUNTIME}" = "k3d" ]; then
    mkdir -p "${CLUSTER_CONFIG_HOST_PATH}/ssl"
    [ "${INSTALL_LOCAL_REGISTRY:=1}" -ne 0 ] || KUBE_NOPROXY_SETTING+=("k3d-${CLUSTER_NAME}-registry")
    LOCAL_REGISTRY_HOST="k3d-${CLUSTER_NAME}-registry" LOCAL_REGISTRY_PORT=5000
  else
    [ "${INSTALL_LOCAL_REGISTRY:=1}" -ne 0 ] || KUBE_NOPROXY_SETTING+=(
      "kubedee-${CLUSTER_NAME}-registry" "registry.local"
    )
    LOCAL_REGISTRY_HOST="registry.local" LOCAL_REGISTRY_PORT=5000
  fi
  [ "${INSTALL_LOCAL_REGISTRY:=1}" -eq 0 ] \
    && K3D_OPTS+=('--registry-create' "${LOCAL_REGISTRY_HOST}:0.0.0.0:${LOCAL_REGISTRY_PORT}") \
    && KUBEDEE_OPTS+=('--enable-insecure-registry') ||:

  [ "${INSTALL_REGISTRY_PROXY}" -ne 0 ] || registry_proxy_pre

  "launch_cluster::${K8S_RUNTIME}"

  [ "${K8S_RUNTIME}" = "k3d" ] && kubectl apply -f "${MYDIR}/utils/manifests/k3d-syslogd.yml" \
    && until kubectl -n kube-system wait --for condition=ready pod -l app=syslog; do sleep 1; done 2>/dev/null ||:
  install_rclone
  export KUBE_API_IP="$(kubectl -n default get svc/kubernetes -o jsonpath='{.spec.clusterIP}')"
}

teardown_cluster::k3d(){
  k3d cluster delete "${CLUSTER_NAME}"
  rm -rf "${CLUSTER_CONFIG_HOST_PATH}"
  echo "${DOCKER_ROOT_FS}" | grep -E '^(btr|tmp)fs$' || [ "$(docker info -f '{{.Driver}}')" = "zfs" ] && docker volume rm -f $(docker volume ls --format '{{.Name}}' | awk "/^${K8S_RUNTIME}-${CLUSTER_NAME}-/") &>/dev/null
}

teardown_cluster::kubedee(){
  "${MYDIR}/kubedee/kubedee" delete "${CLUSTER_NAME}"
}

install_dashboard(){
  declare -A K8S_DASHBOARD=(
    [v1.25]="v2.7.0"
    [v1.24]="v2.6.1"
    [v1.23]="v2.5.1"
    [v1.22]="v2.5.1"
    [v1.21]="v2.4.0"
    [v1.20]="v2.4.0"
    [v1.19]="v2.0.5"
    [v1.18]="v2.0.3"
    [v1.17]="v2.0.0-rc7"
    [v1.16]="v2.0.0-rc3"
    [v1.15]="v2.0.0-beta4"
    [v1.14]="v2.0.0-beta1"
  )
  echo "Installing Dashboard…"
  local KUBELET_VERSION="$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}' | awk -F- '{print $1}')"

  [ "${K8S_DASHBOARD[${KUBELET_VERSION%.*}]+_}" ] \
    && curl -sSL "https://raw.githubusercontent.com/kubernetes/dashboard/${K8S_DASHBOARD[${KUBELET_VERSION%.*}]}/aio/deploy/alternative.yaml" | sed \
      -e '/enable-insecure-login/d' | kubectl apply -f- \
    || (echo "Unsupported Kubelet version ${KUBELET_VERSION%.*}. No dashboard will be installed." && exit 0)
  
  kubectl apply -f "${MYDIR}/utils/manifests/k8s-dashboard-cr.yml"
}

install_service_mesh(){
  kubectl get ns "${NAMESPACES_NETWORK}" &>/dev/null || kubectl create ns "${NAMESPACES_NETWORK}"
  echo "Installing Istio Resources…"

  # be sure to prefix configuration configuration keys with `values.` when using `istioctl`
  #istioctl manifest apply --wait \
  #  --set values.global.proxy.accessLogFile="/dev/stdout"

  # Disables Citadel's SA secret generation for the namespace (unless `security.enableNamespacesByDefault` is already `false` and therefore opt-in)
  #kubectl label ns default ca.istio.io/override=false

  export ENABLE_NETWORK=1 \
    RELEASES_ISTIO_INIT="${RELEASES_ISTIO_INIT:-istio-init}" \
    RELEASES_ISTIO="${RELEASES_ISTIO:-istio}" \
    RELEASES_JAEGER_OPERATOR="${RELEASES_JAEGER_OPERATOR:-jaeger-operator}" \
    RELEASES_ISTIO_BASE="${RELEASES_ISTIO_BASE:-istio-base}" \
    RELEASES_ISTIO_CONTROL="${RELEASES_ISTIO_CONTROL:-istio-control}" \
    RELEASES_ISTIO_GATEWAY_EGRESS="${RELEASES_ISTIO_GATEWAY_EGRESS:-istio-egress}" \
    RELEASES_ISTIO_GATEWAY_INGRESS="${RELEASES_ISTIO_GATEWAY_INGRESS:-istio-ingress}" \
    RELEASES_ISTIO_POLICY="${RELEASES_ISTIO_POLICY:-istio-policy}" \
    RELEASES_ISTIO_TELEMETRY_KIALI="${RELEASES_ISTIO_TELEMETRY_KIALI:-istio-kiali}" \
    RELEASES_ISTIO_TELEMETRY_PROMETHEUS_OPERATOR="${RELEASES_ISTIO_TELEMETRY_PROMETHEUS_OPERATOR:-istio-prometheus-operator}" \
    RELEASES_ISTIO_TELEMETRY_TRACING="${RELEASES_ISTIO_TELEMETRY_TRACING:-istio-tracing}"
}

install_openebs(){
  echo "Installing OpenEBS…"
  local NODE_NAME
  #OPENEBS_OMIT_LOOPDEVS="$(string_join , $(losetup -nlO NAME))"

  if [ "${K8S_RUNTIME}" = "k3d" ]; then
    #docker exec "${K8S_RUNTIME}-${CLUSTER_NAME}-server-0" mkdir -p /run/udev
    #for i in $(seq 0 "$((${NUM_WORKERS}-1))"); do
    #  docker exec "${K8S_RUNTIME}-${CLUSTER_NAME}-agent-${i}" mkdir -p /run/udev
    #done
    for i in $(seq 0 "$((${NUM_WORKERS}-1))"); do
      docker exec "${K8S_RUNTIME}-${CLUSTER_NAME}-server-${i}" mkdir -p /run/udev
    done
  fi
  export RELEASES_OPENEBS="${RELEASES_OPENEBS:-openebs}"
}

install_prometheus_operator(){
  echo "Installing Prometheus Operator…"
  export RELEASES_THANOS="${RELEASES_THANOS:-thanos}" \
    RELEASES_KUBE_PROMETHEUS_STACK="${RELEASES_KUBE_PROMETHEUS_STACK:-kube-prometheus-stack}"
    RELEASES_PROMETHEUS_ADAPTER="${RELEASES_PROMETHEUS_ADAPTER:-prometheus-adapter}"

  NAMESPACES_MONITORING="${NAMESPACES_MONITORING}" \
  envsubst <"${MYDIR}/utils/manifests/thanos-prometheus-query-svc.yml.shtpl" | kubectl apply -f-
}

install_storage(){
  kubectl get secret local-harbor || kubectl create secret docker-registry local-harbor --docker-username=admin --docker-password="${HARBOR_ADMIN_PASSWORD:=Harbor12345}"
  install_openebs
  export ENABLE_STORAGE=1 \
    RELEASES_HARBOR="${RELEASES_HARBOR:-harbor}" \
    RELEASES_PATRONI="${RELEASES_PATRONI:-patroni}" \
    RELEASES_REDIS="${RELEASES_HARBOR:-redis}"
}

install_monitoring(){
  kubectl get ns "${NAMESPACES_MONITORING}" &>/dev/null || kubectl create ns "${NAMESPACES_MONITORING}"
  install_prometheus_operator
  export ENABLE_MONITORING=1 \
    RELEASES_ISTIO_PROMETHEUS_OPERATOR="${RELEASES_ISTIO_PROMETHEUS_OPERATOR:=istio-prometheus-operator}"
}

install_rclone(){
  kubectl apply -f "${MYDIR}/rclone/deploy/kubernetes/1.19"
  # secret config?
}

show_ingress_points::k3d(){
  local NODE_NAME
  for i in $(seq 0 "$((${NUM_WORKERS}-1))"); do
    #[ "${i}" -eq 0 ] && NODE_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-server-0" || NODE_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-agent-$((${i}-1))"
    NODE_NAME="${K8S_RUNTIME}-${CLUSTER_NAME}-server-${i}"
    docker container inspect "${NODE_NAME}" -f "{{(index .NetworkSettings.Networks \"${K8S_RUNTIME}-${CLUSTER_NAME}\").IPAddress}}"
  done
}

show_ingress_points::kubedee(){
  for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-" | grep -Ev '.*-etcd$'); do
    lxc config device get "${i}" eth0 ipv4.address
  done
}

show_ingress_points(){
  echo "Worker node IP addresses:"
  "show_ingress_points::${K8S_RUNTIME}"
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

  [ "${INSTALL_STORAGE}" -ne 0 ] || install_storage
  [ "${INSTALL_SERVICE_MESH}" -ne 0 ] || install_service_mesh
  [ "${INSTALL_MONITORING}" -ne 0 ] || install_monitoring

  # apply helm releases
  local ENDPOINT=$(CLUSTER=$(CTX=$(yq eval '.current-context' <(kubectl config view)) yq eval '.contexts[]|select(.name==env(CTX)).context.cluster' <(kubectl config view)) yq eval '.clusters[]|select(.name==env(CLUSTER)).cluster.server' <(kubectl config view))
  [ -n "${OMIT_HELMFILE}" ] || KUBE_SERVICE_HOST=$(urlparse ${ENDPOINT} | awk -F'|' '{print $4}') KUBE_SERVICE_PORT=$(urlparse ${ENDPOINT} | awk -F'|' '{print $5}') helmfile ${SCRIPT_DEBUG:+--debug --log-level=debug} -b "${HELM_BIN}" --no-color --allow-no-matching-release -f "${MYDIR}/helmfile.yaml" sync --include-transitive-needs --include-needs  #apply ${SCRIPT_DEBUG:+--skip-cleanup}  # https://github.com/helmfile/helmfile/issues/582

  show_ingress_points
  echo "Now run \"kubectl proxy\" and go to http://127.0.0.1:8001/api/v1/namespaces/kubernetes-dashboard/services/http%3Akubernetes-dashboard%3A/proxy/ for your K8S dashboard."
}

kube_down(){
  set +e
  [ "${INSTALL_REGISTRY_PROXY}" -ne 0 ] || docker rm -fv "${REGISTRY_PROXY_HOSTNAME}"
  "teardown_cluster::${K8S_RUNTIME}"
}

declare -A SCRIPT_OPS=(
  [up]="kube_up"
  [down]="kube_down"
)

usage(){
  local MYNAME="$(basename "${0}")"
  cat >&2 <<EOF
${MYNAME%.*} - Linux-centric scaffold for local K8S development

Usage: ${MYNAME} [options] <up|down>

Options:
  --no-*, --with-*                    disable/enable installation of selected
                                      component (choice of: registry-proxy,
                                        monitoring, service-mesh, local-registry,
                                        storage, env: non-zero value on INSTALL_*)
  -N <name>, --name <name>            cluster name (default: ${CLUSTER_NAME},
                                        env: CLUSTER_NAME)
  -n <num>, --num <num>               number of workers (default: \`nproc\`/4,
                                        env: NUM_WORKERS)
  -r <runtime>, --runtime <runtime>   runtime choice (default: ${K8S_RUNTIME},
                                        choice of: k3d, kubedee, env: K8S_RUNTIME)
  -t <tag>, --tag <tag>               set runtime version (env: RUNTIME_TAG)
  -s <pool>, --storage-pool <pool>    LXD storage pool to use with Kubedee
                                        (default: ${LXD_STORAGE_POOL},
                                        env: LXD_STORAGE_POOL)
  --vm                                launch cluster in LXD VMs, instead of LXD
                                        containers (requires \`-r kubedee\`)
  -c <mem>, --controller-mem <mem>    memory to allocate towards K8S controller
                                        (requires \`--vm\`, default: ${CONTROLLER_MEMORY_SIZE},
                                        env: CONTROLLER_MEMORY_SIZE)
  -w <mem>, --worker-mem <mem>        memory to allocate per K8S worker
                                        (requires \`--vm\`, default: ${WORKER_MEMORY_SIZE},
                                        env: WORKER_MEMORY_SIZE)
  -R <size>, --rootfs-size <size>     build rootfs image of provided size
                                        (requires \`--vm\`, default: ${ROOTFS_SIZE},
                                        env: ROOTFS_SIZE)

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

  : ${K8S_RUNTIME:=kubedee}
  : ${CLUSTER_NAME:=k3s-default}
  : ${NUM_WORKERS:=${DEFAULT_WORKERS}}
  : ${LXD_STORAGE_POOL:=default}

  : ${CONTROLLER_MEMORY_SIZE:=2GiB}
  : ${WORKER_MEMORY_SIZE:=19GiB}
  : ${ROOTFS_SIZE:=40GiB}

  while [ "${#}" -gt 0 ]; do
    case "${1}" in
      --no-*)
        COMPONENT="${1/--no-/}"
        COMPONENT="${COMPONENT//-/_}"
        declare INSTALL_${COMPONENT^^}=1
        shift
        ;;
      --with-*)
        COMPONENT="${1/--with-/}"
        COMPONENT="${COMPONENT//-/_}"
        declare INSTALL_${COMPONENT^^}=0
        shift
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
      -N | --name) CLUSTER_NAME="${2}"; shift 2;;
      -t | --tag) RUNTIME_TAG="${2}"; shift 2;;
      -s | --storage-pool) LXD_STORAGE_POOL="${2}"; shift 2;;
      --vm) VM_MODE="--vm --rootfs-size 30GiB"; shift;;
      -c | --controller-mem) CONTROLLER_MEMORY_SIZE="${2}"; shift 2;;
      -w | --worker-mem) WORKER_MEMORY_SIZE="${2}"; shift 2;;
      -R | --rootfs-size) ROOTFS_SIZE="${2}"; shift 2;;
      up | down) SCRIPT_OP="${1}"; shift;;
      *) usage;;
    esac
  done

  export K8S_RUNTIME CLUSTER_NAME
  [ -n "${SCRIPT_OP}" ] || usage

  KUBEDEE_OPTS+=("${VM_MODE}"
    '--rootfs-size' "${ROOTFS_SIZE}"
    '--controller-limits-cpu' $(($(nproc)-1))
    '--controller-limits-memory' "${CONTROLLER_MEMORY_SIZE}"
    '--worker-limits-cpu' $(($(nproc)-1))
    '--worker-limits-memory' "${WORKER_MEMORY_SIZE}"
  )
  K3D_OPTS+=(
    '--agents-memory' "${WORKER_MEMORY_SIZE}"
    '--servers-memory' "${WORKER_MEMORY_SIZE}"  #"${CONTROLLER_MEMORY_SIZE}"
  )
  declare -A NAMESPACES=(
    [monitoring]="${NAMESPACES_MONITORING:=monitoring}"
    [network]="${NAMESPACES_NETWORK:=network}"
    [storage]="${NAMESPACES_STORAGE:=storage}"
  )

  # harbor
  : ${HARBOR_CORE_HOSTNAME:=core.harbor.domain}
  : ${HARBOR_HTTP_NODEPORT:=30002}
  : ${DOCKER_VOLUME_PLUGIN:=ashald/docker-volume-loopback}

  declare -A RUNTIME_VERSIONS=(
    #[k3d]="0.9.1"  # k8s-1.15
    #[k3d]="1.0.1"  # k8s-1.16
    [k3d]="${RUNTIME_TAG:-1.26.1-k3s1}"
    [kubedee]="${RUNTIME_TAG:-1.26.3}"
  )
  echo "${RUNTIME_VERSIONS[k3d]}" | grep -E '^0\.[0-9]\.' && OLD_K3S=0 || OLD_K3S=1
  [ "${OLD_K3S}" -eq 0 ] && SHIM_VERSION=v1 || SHIM_VERSION=v2

  : ${CLUSTER_CONFIG_HOST_PATH:=/var/tmp/k3s/${CLUSTER_NAME}}

  # registry proxy config
  REGISTRY_PROXY_DOCKER_ARGS=()
  : ${REGISTRY_PROXY_HOSTNAME:="${K8S_RUNTIME}-${CLUSTER_NAME}-registry-proxy-cache.local"}
  : ${REGISTRY_PROXY_HOST_PATH:=/var/tmp/oci-registry}
  mkdir -p "${REGISTRY_PROXY_HOST_PATH}"

  # in k3d, the controller node is also a worker, also need to figure out docker as a k3d-specific dep (schu/kubedee#62)
  [ "${K8S_RUNTIME}" = "k3d" ] && BINARY_DEPENDENCIES+=(k3d) || BINARY_DEPENDENCIES+=(lxc cfssl jq)

  # dep check
  for i in ${BINARY_DEPENDENCIES[@]}; do
    command -v "${i}" &>/dev/null || (echo "Missing binary \"${i}\" in PATH, exiting." && exit 1)
  done

  ${SCRIPT_OPS[${SCRIPT_OP}]}
}

main "${@}"
