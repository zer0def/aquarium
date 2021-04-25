#!/bin/bash -e
MYDIR="$(dirname "$(readlink -f "${0}")")"
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
  ['wallaby']='eventlet<0.30.3 zstd<1.5 flask<2.0 typing-extensions<3.10'
)

OS_PROFILES=(infra python3 apache nginx haproxy lvm ceph linuxbridge openvswitch tftp ipxe qemu libvirt)
OS_PIP_ARGS=("--use-feature=in-tree-build")
OS_PIP_PKGS=(
  "psycopg2-binary" "uwsgi"
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
zypper in -ly docker
echo '{"insecure-registries":["${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}"]}' >/etc/docker/daemon.json
systemctl restart docker

docker pull "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/ceph-config-helper:${OS_TAG}" || (docker build --force-rm ${OSH_IMG_COMMON_BUILD_ARGS[@]} \
  -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/ceph-config-helper:${OS_TAG}" \
  --build-arg KUBE_VERSION=v${K8S_VERSION} \
  --build-arg CEPH_RELEASE_TAG="${CEPH_VERSION}-1bionic" \
  -f "${OSH_IMG_LXD_LOCATION}/ceph-config-helper/Dockerfile.ubuntu_bionic" \
  "${OSH_IMG_LXD_LOCATION}/ceph-config-helper" \
&& docker push "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/ceph-config-helper:${OS_TAG}")

docker pull "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/libvirt:${OS_TAG}" || (docker build --force-rm ${OSH_IMG_COMMON_BUILD_ARGS[@]} \
  -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/libvirt:${OS_TAG}" \
  --build-arg FROM=docker.io/ubuntu:focal \
  --build-arg UBUNTU_RELEASE=focal \
  --build-arg CEPH_RELEASE_TAG="${CEPH_VERSION}-1focal" \
  -f "${OSH_IMG_LXD_LOCATION}/libvirt/Dockerfile.ubuntu_bionic" \
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

    #--build-arg WHEELS="${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/requirements:${OS_TAG}"
for i in keystone glance cinder neutron nova placement horizon heat barbican octavia designate manila ironic magnum senlin trove; do
  docker pull "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/\${i}:${OS_TAG}" || (docker build --force-rm ${LOCI_COMMON_BUILD_ARGS[@]} \
    -t "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/\${i}:${OS_TAG}" \
    --build-arg PROJECT="\${i}" \
    --build-arg PROFILES="requirements ${OS_PROFILES[@]}" \
    "${LOCI_LXD_LOCATION}" \
  && docker push "${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}/openstack/\${i}:${OS_TAG}")
done
wait \$(jobs -rp)
systemctl stop docker
zypper rm -uy docker
EOF
}

up(){
  "${MYDIR}/../kubedee/kubedee" up "${CLUSTER_NAME}" \
    --apiserver-extra-hostnames "kubernetes.default,kubernetes.default.svc,kubernetes.default.svc.cluster.local" \
    --enable-insecure-registry --vm \
    --num-worker "${NUM_WORKERS}" \
    --kubernetes-version "v${K8S_VERSION}" \
    --controller-limits-memory "${CONTROLLER_MEMORY_SIZE}" \
    --worker-limits-memory "${WORKER_MEMORY_SIZE}" \
    --storage-pool "${LXD_STORAGE_POOL}" \
    --rootfs-size "30GiB"

  export LOCAL_REGISTRY_HOST="kubedee-${CLUSTER_NAME}-registry" \
    LOCAL_REGISTRY_PORT="5000"

  KUBE_NOPROXY_SETTING+=("${LOCAL_REGISTRY_HOST}")

  if false; then
    registry_proxy_post::kubedee
    for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-" | grep -Ev '.*-(etcd|registry)$'); do
      lxc exec "${i}" -- /bin/sh -c 'systemctl daemon-reload; systemctl restart crio'

      #iptables -I FORWARD -o docker0 -i kubedee-8lpln6 -j ACCEPT
      #iptables -I FORWARD -o kubedee-8lpln6 -i docker0 -j ACCEPT
    done

    until kubectl -n kube-system wait --for condition=ready pod -l app=flannel,tier=node; do sleep 1; done 2>/dev/null
    until kubectl -n kube-system wait --for condition=ready pod -l k8s-app=kube-dns; do sleep 1; done 2>/dev/null
  fi

  [ -z "${POPULATE_LOCAL_REGISTRY}" ] || populate_local_registry

  # volume setup
  local i j
  for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-worker-"); do
    lxc exec "${i}" -- zypper in -ly lvm2
    lxc stop "${i}" ||:
    for j in {b..g}; do
      lxc storage volume create "${LXD_STORAGE_POOL}" "${i}-sd${j}" size="${VOLUME_SIZE}" --type block
      [ -n "$(lxc config device get "${i}" "${i}-sd${j}" source)" ] || until lxc storage volume attach "${LXD_STORAGE_POOL}" "${i}-sd${j}" "${i}" ''; do :; done
    done
    lxc start "${i}"
  done

  #export CEPH_MON_COUNT="${NUM_WORKERS}"
  #if [ "${CEPH_MON_COUNT}" -gt 3 ]; then CEPH_MON_COUNT=3; fi

  $("${MYDIR}/../kubedee/kubedee" kubectl-env "${CLUSTER_NAME}")
  setup_helm

  #ROOK_NETWORK="$(lxc network get "$(cat ~/.local/share/kubedee/clusters/rookery/network_id)" ipv4.address)" \
  LOCAL_REGISTRY_ADDRESS="${LOCAL_REGISTRY_HOST}:${LOCAL_REGISTRY_PORT}" \
  helmfile -b "${HELM_BIN}" --no-color --allow-no-matching-release -f "${MYDIR}/helmfile.yaml" sync

  "${MYDIR}/../kubedee/kubedee" kubectl-env "${CLUSTER_NAME}"
}

down(){
  set +e
  "${MYDIR}/../kubedee/kubedee" delete "${CLUSTER_NAME}"
  docker rm -fv "${REGISTRY_PROXY_HOSTNAME}"
  for i in $(lxc storage volume list "${LXD_STORAGE_POOL}" --format csv | awk -F, "/(^|,)kubedee-${CLUSTER_NAME}-worker-/ {print \$2}"); do
    lxc storage volume delete "${LXD_STORAGE_POOL}" "${i}"
  done
  set -e
}

main(){
  : ${LXD_STORAGE_POOL:=default}
  : ${CLUSTER_NAME:=rookery}
  : ${NUM_WORKERS:=1}
  : ${K8S_VERSION:=1.21.1}
  : ${OS_VERSION:=wallaby}
  : ${BASE_IMAGE:=ubuntu_bionic}
  : ${CONTROLLER_MEMORY_SIZE:=2GiB}
  : ${WORKER_MEMORY_SIZE:=12GiB}
  : ${CEPH_VERSION:=16.2.4}
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
      -N | --name) CLUSTER_NAME="${2}"; shift 2;;
      -V | --version) K8S_VERSION="${2}"; shift 2;;
      -s | --storage-pool) LXD_STORAGE_POOL="${2}"; shift 2;;
      -o | --openstack-version) OS_VERSION="${2}"; shift 2;;
      -b | --base-image) BASE_IMAGE="${2}"; shift 2;;
      -c | --controller-mem) CONTROLLER_MEMORY_SIZE="${2}"; shift 2;;
      -w | --worker-mem) WORKER_MEMORY_SIZE="${2}"; shift 2;;
      -C | --ceph-version) CEPH_VERSION="${2}"; shift 2;;
      -p | --populate-local-registry) POPULATE_LOCAL_REGISTRY="y"; shift;;
      up | down) SCRIPT_OP="${1}"; shift;;
      *) usage;;
    esac
  done
  [ -z "${SCRIPT_OP}" ] && usage

  export BASE_IMAGE CEPH_VERSION OS_VERSION \
      OS_TAG="${OS_VERSION}-${BASE_IMAGE}" \
      VOLUME_SIZE="${VOLUME_SIZE:-15GiB}"
  : ${REGISTRY_PROXY_HOSTNAME:="kubedee-${CLUSTER_NAME}-registry-proxy-cache.local"}
  : ${REGISTRY_PROXY_HOST_PATH:=/var/tmp/oci-registry}

  "${SCRIPT_OP}"
}
main "${@}"
