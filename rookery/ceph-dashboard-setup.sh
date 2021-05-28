#!/bin/sh -ex

# https://docs.ceph.com/en/latest/mgr/dashboard/
CEPH_NS="${CEPH_NS:-rook-ceph}"
CEPH_DASH_PORT="${CEPH_DASH_PORT:-7000}"
[ -n "${CEPH_POD}" ] || CEPH_POD="$(kubectl -n "${CEPH_NS}" get pod -l app="${CEPH_NS}-tools" -o jsonpath='{.items[*].metadata.name}' | awk '{print $1}' | head -n1)"
[ -n "${CEPH_PWD}" ] || CEPH_PWD="$(kubectl -n "${CEPH_NS}" get secret "${CEPH_NS}-dashboard-password" -o jsonpath='{.data.password}' | base64 -dw0)"

cat <<EOF | kubectl -n "${CEPH_NS}" exec -ti ${CEPH_POD} -- /bin/sh -ex
ceph mgr module disable dashboard
ceph config set mgr mgr/dashboard/server_port "${CEPH_DASH_PORT}"
ceph config set mgr mgr/dashboard/ssl false
ceph dashboard ac-user-create "${CEPH_USER:-admin}" -i <(echo '${CEPH_PWD}') administrator
ceph mgr module enable dashboard
EOF
kubectl -n "${CEPH_NS}" port-forward "svc/${CEPH_NS}-mgr-dashboard" 7000:"${CEPH_DASH_PORT}"
