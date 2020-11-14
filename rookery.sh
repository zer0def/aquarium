#!/bin/bash -e
[ "${SCRIPT_DEBUG:-1}" -eq 0 ] && set -x && export KUBEDEE_DEBUG=1
MYDIR="$(dirname "$(readlink -f "${0}")")"

CLUSTER_NAME="${CLUSTER_NAME:-rookery}"
NUM_WORKERS="${NUM_WORKERS:-3}"
K8S_VERSION="${K8S_VERSION:-1.19.4}"
LXD_STORAGE_POOL="${LXD_STORAGE_POOL:-default}"
export VOLUME_SIZE="${VOLUME_SIZE:-15GiB}"
MEMORY_SIZE="${MEMORY_SIZE:-4GiB}"
#NUM_VOLUMES="${NUM_VOLUMES:-2}"

DEFAULT_PROXY_REGISTRIES=(
  k8s.gcr.io gcr.io quay.io "registry.opensource.zalan.do"
)
REGISTRY_PROXY_REPO="${REGISTRY_PROXY_REPO:="rpardini/docker-registry-proxy:0.6.0"}"
REGISTRY_PROXY_HOSTNAME="${REGISTRY_PROXY_HOSTNAME:="kubedee-${CLUSTER_NAME}-registry-proxy-cache.local"}"
REGISTRY_PROXY_HOST_PATH="${REGISTRY_PROXY_HOST_PATH:=/var/tmp/oci-registry}"

usage(){
  exit 0
}

string_join() { local IFS="$1"; shift; echo "$*"; }

setup_helm(){
  declare -A HELM_PLUGINS=(
    ['https://github.com/hypnoglow/helm-s3']="v0.9.2"
    ['https://github.com/zendesk/helm-secrets']="v2.0.2"
    ['https://github.com/aslafy-z/helm-git']="v0.8.1"
    ['https://github.com/databus23/helm-diff']="v3.1.3"
    ['https://github.com/hayorov/helm-gcs']="0.3.6"
  )
  helm version --template '{{.Version}}' | grep -E '^v3\.' || TILLER_SERVICE_ACCOUNT="tiller"
  # Helm v2: `helm version -c --template '{{.Client.SemVer}}'`
  [ -n "${TILLER_SERVICE_ACCOUNT}" ] && HELM_PLUGINS['https://github.com/rimusz/helm-tiller']="v0.9.3" && install_tiller

  echo "Installing Helm plugins…"
  for i in "${!HELM_PLUGINS[@]}"; do helm plugin install "${i}" --version "${HELM_PLUGINS[${i}]}" ||:; done
}

install_tiller(){
  echo "Installing Tiller…"
  kubectl apply -f- <<EOF
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${TILLER_SERVICE_ACCOUNT}
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${TILLER_SERVICE_ACCOUNT}-cluster-admin-crb
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: ${TILLER_SERVICE_ACCOUNT}
  namespace: kube-system
EOF

  helm init --upgrade --service-account "${TILLER_SERVICE_ACCOUNT}"
  until kubectl -n kube-system wait --for condition=available deploy tiller-deploy; do sleep 1; done 2>/dev/null
}

registry_proxy(){
  local REGISTRIES="${PROXY_REGISTRIES:=${DEFAULT_PROXY_REGISTRIES[@]}}" AUTH_REGISTRIES="${PROXY_REGISTRIES_AUTH}" TARGET_FILE="${1}"
  docker run -d \
    --name "${REGISTRY_PROXY_HOSTNAME}" \
    -v "${REGISTRY_PROXY_HOST_PATH}:/docker_mirror_cache" \
    -e "REGISTRIES=${REGISTRIES}" \
    -e "AUTH_REGISTRIES=${AUTH_REGISTRIES}" \
    -e "ENABLE_MANIFEST_CACHE=true" \
    -e 'MANIFEST_CACHE_PRIMARY_REGEX=.*' \
    -e 'MANIFEST_CACHE_PRIMARY_TIME=6h' \
    -e 'MANIFEST_CACHE_SECONDARY_REGEX=.*' \
    -e 'MANIFEST_CACHE_SECONDARY_TIME=6h' \
    -e 'MANIFEST_CACHE_DEFAULT_TIME=6h' \
    "${REGISTRY_PROXY_REPO}" &>/dev/null
  docker exec "${REGISTRY_PROXY_HOSTNAME}" /bin/sh -c 'until test -f /ca/ca.crt; do sleep 1; done; cat /ca/ca.crt' >> "${TARGET_FILE}"
}

up(){
  [ "$(lxd --version)" = "4.8" ] && "Custom block volume attachment is broken since LXD 4.8. Exiting…" && exit 0 ||:
  "${MYDIR}/kubedee/kubedee" up "${CLUSTER_NAME}" --enable-insecure-registry --vm --num-worker "${NUM_WORKERS}" --kubernetes-version "v${K8S_VERSION}" --limits-memory "${MEMORY_SIZE}" --storage-pool "${LXD_STORAGE_POOL}"

  # registry proxy setup
  local TMP_CA="$(mktemp)" TMP_SYSTEMD_SVC="$(mktemp)" \
    CACERT_PATH="/var/lib/ca-certificates/ca-bundle.pem"
    #CACERT_PATH="/etc/ssl/certs/ca-certificates.crt"
  lxc file pull "kubedee-${CLUSTER_NAME}-controller${CACERT_PATH}" "${TMP_CA}"
  chmod u+w "${TMP_CA}"
  mkdir -p "${REGISTRY_PROXY_HOST_PATH}"

  registry_proxy "${TMP_CA}"

  local REGISTRY_PROXY_ADDRESS="$(docker container inspect "${REGISTRY_PROXY_HOSTNAME}" -f '{{.NetworkSettings.IPAddress}}')"
  cat <<EOF >"${TMP_SYSTEMD_SVC}"
[Service]
Environment="HTTP_PROXY=http://${REGISTRY_PROXY_ADDRESS}:3128/"
Environment="HTTPS_PROXY=http://${REGISTRY_PROXY_ADDRESS}:3128/"
Environment="NO_PROXY=$(string_join , ${KUBE_NOPROXY_SETTING[@]})"
EOF

  lxc file push "${TMP_CA}" "kubedee-${CLUSTER_NAME}-controller${CACERT_PATH}"
  lxc file push "${TMP_SYSTEMD_SVC}" "kubedee-${CLUSTER_NAME}-controller/etc/systemd/system/crio.service.d/registry-proxy.conf" -p
  lxc exec "kubedee-${CLUSTER_NAME}-controller" -- /bin/sh -c 'systemctl daemon-reload; systemctl restart crio'

  # volume setup
  local i j
  for i in $(lxc list -cn --format csv | grep -E "^kubedee-${CLUSTER_NAME}-worker-"); do
    lxc exec "${i}" -- zypper in -ly lvm2
    lxc file push "${TMP_CA}" "${i}${CACERT_PATH}"
    lxc file push "${TMP_SYSTEMD_SVC}" "${i}/etc/systemd/system/crio.service.d/registry-proxy.conf" -p
    lxc stop "${i}" ||:
    for j in {b..c}; do
      lxc storage volume create "${LXD_STORAGE_POOL}" "${i}-sd${j}" size="${VOLUME_SIZE}" --type block
      until lxc storage volume attach "${LXD_STORAGE_POOL}" "${i}-sd${j}" "${i}" "sd${j}"; do :; done
    done
    lxc start "${i}"
  done

  rm "${TMP_CA}" "${TMP_SYSTEMD_SVC}"

  export CEPH_MON_COUNT="${NUM_WORKERS}"
  if [ "${CEPH_MON_COUNT}" -gt 3 ]; then CEPH_MON_COUNT=3; fi

  $("${MYDIR}/kubedee/kubedee" kubectl-env "${CLUSTER_NAME}")
  setup_helm
  local LOCAL_REGISTRY_ADDRESS="$(lxc list -cn4 --format csv | awk -F, "/^kubedee-${CLUSTER_NAME}-registry,/ {print \$NF}")"
  LOCAL_REGISTRY_ADDRESS="${LOCAL_REGISTRY_ADDRESS% *}:5000" helmfile -f "${MYDIR}/ceph-helmfile.yaml" sync
  "${MYDIR}/kubedee/kubedee" kubectl-env "${CLUSTER_NAME}"
}

down(){
  "${MYDIR}/kubedee/kubedee" delete "${CLUSTER_NAME}" ||:
  docker rm -fv "${REGISTRY_PROXY_HOSTNAME}" ||:
  for i in $(lxc storage volume list "${LXD_STORAGE_POOL}" --format csv | awk -F, "/(^|,)kubedee-${CLUSTER_NAME}-worker-/ {print \$2}"); do
    lxc storage volume delete "${LXD_STORAGE_POOL}" "${i}"
  done
}

main(){
  local SCRIPT_OP
  while [ "${#}" -gt 0 ]; do
    case "${1}" in
      up | down)
        SCRIPT_OP="${1}"
        shift
        ;;
      *) usage;;
    esac
  done
  [ -z "${SCRIPT_OP}" ] && usage
  "${SCRIPT_OP}"
}
main "${@}"
