#!/bin/bash -e
if [ -n "${SCRIPT_DEBUG}" ]; then
  set -x
  export KUBEDEE_DEBUG=1
fi
export MYDIR="$(dirname "$(readlink -f "${0}")")"
. "${MYDIR}/../common"

usage(){
  local MYNAME="$(basename "${0}")"
  cat >&2 <<EOF
${MYNAME%.*} - Openstack+Ceph-on-K8S dev environment on LXD VMs via Kubedee

Usage: ${0} [options] <up|down>

Options:
  -N <name>, --name <name>              cluster name
                                        (default: ${CLUSTER_NAME}, env: CLUSTER_NAME)
  -n <num>, --num <num>                 number of workers
                                        (default: ${NUM_WORKERS}, env: NUM_WORKERS)
  -V <tag>, --tag <tag>                 Kubernetes version to use
                                        (default: ${K8S_VERSION}, env: K8S_VERSION)
  -s <pool>, --storage-pool <pool>      LXD storage pool to use for the K8S cluster
                                        (default: ${LXD_STORAGE_POOL}, env: LXD_STORAGE_POOL)
  -o <tag>, --openstack-version <tag>   Openstack version to deploy
                                        (default: ${OS_VERSION}, env: OS_VERSION)
  -b <base>, --base-image <base>        base LOCI image to use for Openstack
                                        images (default: ${BASE_IMAGE}, env: BASE_IMAGE)
  -c <mem>, --controller-mem <mem>      memory to allocate towards K8S controller
                                        (default: ${CONTROLLER_MEMORY_SIZE}, env: CONTROLLER_MEMORY_SIZE)
  -w <mem>, --worker-mem <mem>          memory to allocate per K8S worker
                                        (default: ${WORKER_MEMORY_SIZE}, env: WORKER_MEMORY_SIZE)
  -C <semver>, --ceph-version <semver>  Ceph package version to use
                                        (default: ${CEPH_VERSION}, env CEPH_VERSION)
EOF
  exit 1
}

declare -A STABLE_VERSION_REQUIREMENTS=(
  ['victoria']='neutron-lib<2.7.0'
  ['wallaby']='eventlet<0.30.3 zstd<1.5 flask<2.0 typing-extensions<3.10 XStatic-Angular<1.8.2.1'
  ['xena']='eventlet<0.30.3 typing-extensions<3.10 XStatic-Angular<1.8.2.1'  # typing-extensions only for bionic?
)

OS_PROFILES=(infra python3 apache nginx haproxy lvm ceph linuxbridge openvswitch tftp ipxe qemu libvirt)
OS_PIP_ARGS=(
  #"--use-feature=in-tree-build"
)
OS_PIP_PKGS=(
  "psycopg2-binary<2.9"  # https://github.com/psycopg/psycopg2/issues/1293
  "uwsgi"
  #"psycopg2cffi" "psycogreen" "pg8000<=1.16.5"
)

#until kubectl wait --for condition=complete job "k3d-${CLUSTER_NAME}-server"; do sleep 1; done 2>/dev/null

populate_local_registry(){
  local LOCI_LXD_LOCATION="/tmp/loci" \
    OSH_IMG_LXD_LOCATION="/tmp/openstack-helm-images" \
    TMP_SYSTEMD_SVC="$(mktemp)" \
    BUILDER_HOST="kubedee-${CLUSTER_NAME}-controller"
    #BUILDER_HOST="$(lxc ls -cn --format csv | awk "/^kubedee-${CLUSTER_NAME}-worker-/" | head -n1)"

  cat <<EOF >"${TMP_SYSTEMD_SVC}"
[Service]
Environment="HTTP_PROXY=http://${REGISTRY_PROXY_ADDRESS}:3128/"
Environment="HTTPS_PROXY=http://${REGISTRY_PROXY_ADDRESS}:3128/"
Environment="NO_PROXY=${LOCAL_REGISTRY_HOST}"
EOF

  lxc file push -pr "${MYDIR}/../images/loci" "${BUILDER_HOST}${LOCI_LXD_LOCATION%/*}"
  lxc file push -pr "${MYDIR}/../images/openstack-helm-images" "${BUILDER_HOST}${OSH_IMG_LXD_LOCATION%/*}"
  lxc file push -pr "${TMP_SYSTEMD_SVC}" "${BUILDER_HOST}/etc/systemd/system/docker.service.d/registry-proxy.conf"

  OSH_IMG_COMMON_BUILD_ARGS=(
    "--build-arg" "CEPH_KEY=https://download.ceph.com/keys/release.asc"
    "--build-arg" "CEPH_REPO=https://download.ceph.com/debian-${CEPH_VERSION}/"
    "--build-arg" "CEPH_RELEASE=${CEPH_VERSION}"
    "--build-arg" "FROM=docker.io/ubuntu:${BASE_IMAGE#*_}"
    "--build-arg" "DISTRO_CODENAME=${BASE_IMAGE#*_}"
    "--build-arg" "UBUNTU_RELEASE=${BASE_IMAGE#*_}"
  )
  LOCI_COMMON_BUILD_ARGS=(
    "--build-arg" "FROM='${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/loci-base:${OS_TAG}'"
    "--build-arg" "PYTHON3=yes"
    "--build-arg" "PROJECT_REF='stable/${OS_VERSION}'"
    "--build-arg" "PROJECT_RELEASE='${OS_VERSION}'"
    "--build-arg" "PIP_PACKAGES='${OS_PIP_PKGS[@]} ${STABLE_VERSION_REQUIREMENTS[${OS_VERSION}]}'"
    "--build-arg" "PIP_ARGS='${OS_PIP_ARGS[@]}'"
  )

  lxc exec "${BUILDER_HOST}" -- /bin/bash -ex <<EOF
#zypper in -ly docker
DEBIAN_FRONTEND=noninteractive apt -y --no-install-recommends install docker.io
echo '{"insecure-registries":["${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}"]}' >/etc/docker/daemon.json
systemctl restart docker

docker pull "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/ceph-config-helper:${OS_TAG}" || (docker build --force-rm ${OSH_IMG_COMMON_BUILD_ARGS[@]} \
  -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/ceph-config-helper:${OS_TAG}" \
  --build-arg KUBE_VERSION=v${K8S_VERSION} \
  -f "${OSH_IMG_LXD_LOCATION}/ceph-config-helper/Dockerfile.${BASE_IMAGE}" \
  "${OSH_IMG_LXD_LOCATION}/ceph-config-helper" \
&& docker push "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/ceph-config-helper:${OS_TAG}")

docker pull "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/libvirt:${OS_TAG}" || (docker build --force-rm ${OSH_IMG_COMMON_BUILD_ARGS[@]} \
  -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/libvirt:${OS_TAG}" \
  --build-arg UBUNTU_CLOUD_ARCHIVE_RELEASE="${UBUNTU_CLOUD_ARCHIVE_RELEASE:-yoga-proposed}" \
  -f "${OSH_IMG_LXD_LOCATION}/libvirt/Dockerfile.${BASE_IMAGE}" \
  "${OSH_IMG_LXD_LOCATION}/libvirt" \
&& docker push "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/libvirt:${OS_TAG}")

docker build --force-rm \
  -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/loci-base:${OS_TAG}" \
  --build-arg CEPH_URL="http://download.ceph.com/debian-${CEPH_VERSION}/" \
  "${LOCI_LXD_LOCATION}/dockerfiles/${BASE_IMAGE}"

#docker build --force-rm ${LOCI_COMMON_BUILD_ARGS[@]} \
#  -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/requirements:${OS_TAG}" \
#  --build-arg PROJECT=requirements \
#  --build-arg PROFILES="${OS_PROFILES[@]}" \
#  "${LOCI_LXD_LOCATION}" \
#&& docker push "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/requirements:${OS_TAG}"

#docker pull "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/gnocchi:${OS_TAG}" || (docker build --force-rm \
#  -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/gnocchi:${OS_TAG}" \
#  --build-arg PROFILES="requirements ${OS_PROFILES[@]}" \
#  --build-arg FROM='${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/loci-base:${OS_TAG}' \
#  --build-arg PYTHON3=yes \
#  --build-arg PIP_ARGS='${OS_PIP_ARGS[@]}' \
#  --build-arg PROJECT_RELEASE='${OS_VERSION}' \
#  --build-arg PROJECT="gnocchi" \
#  --build-arg PIP_PACKAGES='${OS_PIP_PKGS[@]} ${STABLE_VERSION_REQUIREMENTS[${OS_VERSION}]} /tmp/gnocchi[keystone,mysql,postgresql,s3,redis,swift,ceph,prometheus,amqp1] tooz[consul,etcd,etcd3,etcd3gw,redis,postgresql,mysql,zookeeper,memcached]' \
#  --build-arg PROJECT_REPO="https://github.com/gnocchixyz/gnocchi" \
#  --build-arg PROJECT_REF="stable/4.4" \
#  "${LOCI_LXD_LOCATION}" \
#&& docker push "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/gnocchi:${OS_TAG}")

    #--build-arg WHEELS="${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/requirements:${OS_TAG}"
for i in keystone glance cinder neutron nova placement heat octavia ceilometer aodh designate; do  #barbican manila ironic magnum senlin trove; do
  docker pull "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/\${i}:${OS_TAG}" || (docker build --force-rm ${LOCI_COMMON_BUILD_ARGS[@]} \
    -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/\${i}:${OS_TAG}" \
    --build-arg PROJECT="\${i}" \
    --build-arg PROFILES="requirements ${OS_PROFILES[@]}" \
    "${LOCI_LXD_LOCATION}" \
  && docker push "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/\${i}:${OS_TAG}")
done
wait \$(jobs -rp)

docker pull "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/horizon:${OS_TAG}" || (docker build --force-rm \
  -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/horizon:${OS_TAG}" \
  --build-arg FROM='${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/loci-base:${OS_TAG}' \
  --build-arg PYTHON3=yes \
  --build-arg PROJECT_REF='stable/${OS_VERSION}' \
  --build-arg PROJECT_RELEASE='${OS_VERSION}' \
  --build-arg PIP_ARGS='${OS_PIP_ARGS[@]}' \
  --build-arg PIP_PACKAGES='${OS_PIP_PKGS[@]} ${STABLE_VERSION_REQUIREMENTS[${OS_VERSION}]} adjutant-ui blazar-dashboard cloudkitty-dashboard designate-dashboard heat-dashboard masakari-dashboard mistral-dashboard murano-dashboard neutron-vpnaas-dashboard octavia-dashboard sahara-dashboard senlin-dashboard solum-dashboard trove-dashboard vitrage-dashboard watcher-dashboard' \
  --build-arg PROJECT="horizon" \
  --build-arg PROFILES="requirements ${OS_PROFILES[@]}" \
  "${LOCI_LXD_LOCATION}" \
&& docker push "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/horizon:${OS_TAG}")

systemctl stop docker
#zypper rm -uy docker
DEBIAN_FRONTEND=noninteractive apt -y purge docker.io
ip link delete docker0
EOF
}

up(){
  #HTTP_PROXY="http://${REGISTRY_PROXY_HOSTNAME}:3128" \
  #HTTPS_PROXY="http://${REGISTRY_PROXY_HOSTNAME}:3128" \
  #NO_PROXY="$(string_join , ${KUBE_NOPROXY_SETTING[@]})" \
  "${MYDIR}/../kubedee/kubedee" up "${CLUSTER_NAME}" \
    --apiserver-extra-hostnames "kubernetes.default,kubernetes.default.svc,kubernetes.default.svc.cluster.local" \
    --enable-insecure-registry --vm --routed \
    --num-worker "${NUM_WORKERS}" \
    --kubernetes-version "v${K8S_VERSION}" \
    --controller-limits-cpu $(($(nproc)-1)) \
    --controller-limits-memory "${CONTROLLER_MEMORY_SIZE}" \
    --worker-limits-cpu $(($(nproc)-1)) \
    --worker-limits-memory "${WORKER_MEMORY_SIZE}" \
    --storage-pool "${LXD_STORAGE_POOL}" \
    --rootfs-size "48GiB"

  export LOCAL_REGISTRY_HOST="kubedee-${CLUSTER_NAME}-registry" LOCAL_REGISTRY_PORT="5000"

  KUBE_NOPROXY_SETTING+=("${LOCAL_REGISTRY_HOST}")
  local KUBEDEE_NET="$(cat "${HOME}/.local/share/kubedee/clusters/${CLUSTER_NAME}/network_id")"
  #lxc network create "kd-ext-${KUBEDEE_NET##*-}" ipv6.address=none ipv4.address=172.24.4.1/24

  if true; then
    registry_proxy_post::kubedee
    for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-" | grep -Ev '.*-(etcd|registry)$'); do
      lxc exec "${i}" -- /bin/sh -c 'systemctl daemon-reload; systemctl restart crio'

      #iptables -I FORWARD 1 -o docker0 -i "$(cat "${HOME}/.local/share/kubedee/clusters/${CLUSTER_NAME}/network_id")" -j ACCEPT
      #iptables -I FORWARD 1 -o "$(cat "${HOME}/.local/share/kubedee/clusters/${CLUSTER_NAME}/network_id")" -i docker0 -j ACCEPT
    done

    until kubectl -n kube-system wait --for condition=ready pod -l app=flannel,tier=node; do sleep 1; done 2>/dev/null
    until kubectl -n kube-system wait --for condition=ready pod -l k8s-app=kube-dns; do sleep 1; done 2>/dev/null
  fi

  [ -z "${POPULATE_LOCAL_REGISTRY}" ] || populate_local_registry

  local i j
  for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-worker-"); do
#    lxc exec "${i}" -- /bin/sh <<'EOF'
##zypper in -ly lvm2 open-iscsi
#DEBIAN_FRONTEND=noninteractive apt -y --no-install-recommends install lvm2 open-iscsi
## http://blog.father.gedow.net/2013/05/21/ceph-as-cinder-storage/
#InitiatorName=$(iscsi-iname) > /etc/iscsi/initiatorname.iscsi
#EOF
    lxc stop "${i}" ||:
    #lxc config device add "${i}" eth1 nic name=eth1 network="kd-ext-${KUBEDEE_NET##*-}"
    #lxc network attach "kd-ext-${KUBEDEE_NET##*-}" "${i}" eth1 eth1
    for j in {b..g}; do
      local volname="${CLUSTER_NAME}-${i##*-}-${j}"  # "${volname:${voltrunc}:27}"
      [ "$((${#volname}-27))" -ge 0 ] && voltrunc="$((${#volname}-27))" || voltrunc=0
      lxc storage volume create "${LXD_STORAGE_POOL}" "${volname:${voltrunc}:27}" size="${VOLUME_SIZE}" --type block &>/dev/null
      [ -n "$(lxc config device get "${i}" "${i}-sd${j}" source 2>/dev/null )" ] || until lxc storage volume attach "${LXD_STORAGE_POOL}" "${volname:${voltrunc}:27}" "${i}" '' &>/dev/null; do :; done
    done
    lxc start "${i}"
    until lxc exec "${i}" -- hostname &>/dev/null; do lxc restart -f "${i}"; echo "Waiting for ${i} to boot after attaching additional volumes..."; sleep 15; done
  done

  #export CEPH_MON_COUNT="${NUM_WORKERS}"
  #if [ "${CEPH_MON_COUNT}" -gt 3 ]; then CEPH_MON_COUNT=3; fi

  $("${MYDIR}/../kubedee/kubedee" kubectl-env "${CLUSTER_NAME}")
  setup_helm

  #ROOK_NETWORK="$(lxc network get "$(cat ~/.local/share/kubedee/clusters/rookery/network_id)" ipv4.address)" \
  #KUBE_API_IP="$(kubectl -n default get svc/kubernetes -o jsonpath='{.spec.clusterIP}')" \
  LOCAL_REGISTRY_ADDRESS="${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}" \
  helmfile ${SCRIPT_DEBUG:+--debug} -b "${HELM_BIN}" --no-color --allow-no-matching-release -f "${MYDIR}/helmfile.yaml" apply ${SCRIPT_DEBUG:+--skip-cleanup}

  "${MYDIR}/../kubedee/kubedee" kubectl-env "${CLUSTER_NAME}"
  # ceph progress clear during "Global Recovery Event" in Ceph cluster  # https://tracker.ceph.com/issues/49988
}

down(){
  set +e
  local KUBEDEE_NET="$(cat "${HOME}/.local/share/kubedee/clusters/${CLUSTER_NAME}/network_id")"
  "${MYDIR}/../kubedee/kubedee" delete "${CLUSTER_NAME}"
  #lxc network show "kd-ext-${KUBEDEE_NET##*-}" && \
  #lxc network delete "kd-ext-${KUBEDEE_NET##*-}"
  docker rm -fv "${REGISTRY_PROXY_HOSTNAME}"
  for i in $(lxc storage volume list "${LXD_STORAGE_POOL}" --format csv | awk -F, "/(^|,)(kubedee-${CLUSTER_NAME}-worker|${CLUSTER_NAME})-/ {print \$2}"); do
    lxc storage volume delete "${LXD_STORAGE_POOL}" "${i}"
  done
  set -e
}

main(){
  : ${LXD_STORAGE_POOL:=default}
  : ${CLUSTER_NAME:=rookery}
  : ${NUM_WORKERS:=2}
  : ${K8S_VERSION:=1.26.2}
  : ${OS_VERSION:=zed}
  : ${BASE_IMAGE:=ubuntu_focal}
  : ${CONTROLLER_MEMORY_SIZE:=4GiB}
  : ${WORKER_MEMORY_SIZE:=18GiB}
  : ${CEPH_VERSION:=17.2.5}
  #NUM_VOLUMES="${NUM_VOLUMES:-2}"

  local SCRIPT_OP
  while [ "${#}" -gt 0 ]; do
    case "${1}" in
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
      -N | --name)                    CLUSTER_NAME="${2}";           shift 2;;
      -V | --version)                 K8S_VERSION="${2}";            shift 2;;
      -s | --storage-pool)            LXD_STORAGE_POOL="${2}";       shift 2;;
      -o | --openstack-version)       OS_VERSION="${2}";             shift 2;;
      -b | --base-image)              BASE_IMAGE="${2}";             shift 2;;
      -c | --controller-mem)          CONTROLLER_MEMORY_SIZE="${2}"; shift 2;;
      -w | --worker-mem)              WORKER_MEMORY_SIZE="${2}";     shift 2;;
      -C | --ceph-version)            CEPH_VERSION="${2}";           shift 2;;
      -p | --populate-local-registry) POPULATE_LOCAL_REGISTRY="y";   shift;;
      up | down)                      SCRIPT_OP="${1}";              shift;;
      *) usage;;
    esac
  done
  [ -z "${SCRIPT_OP}" ] && usage

  export BASE_IMAGE CEPH_VERSION OS_VERSION \
      OS_TAG="${OS_VERSION}-${BASE_IMAGE}" \
      VOLUME_SIZE="${VOLUME_SIZE:-10GiB}"
  : ${REGISTRY_PROXY_HOSTNAME:="kubedee-${CLUSTER_NAME}-registry-proxy-cache.local"}
  : ${REGISTRY_PROXY_HOST_PATH:=/var/tmp/oci-registry}

  "${SCRIPT_OP}"
}
main "${@}"
