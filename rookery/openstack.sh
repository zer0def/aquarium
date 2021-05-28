#!/bin/bash -ex

HEAT_ENGINE_NS="${HEAT_ENGINE_NS:-openstack}"
[ -n "${HEAT_ENGINE_POD}" ] || HEAT_ENGINE_POD="$(kubectl -n "${HEAT_ENGINE_NS}" get pod -l application=heat,component=engine -o jsonpath='{.items[*].metadata.name}' | awk '{print $1}' | head -n1)"

kubectl -n "${HEAT_ENGINE_NS}" exec -ti "${HEAT_ENGINE_POD}" -- \
  OS_IDENTITY_API_VERSION=3 \
  OS_AUTH_URL=http://keystone-api.openstack.svc.cluster.local:5000/v3 \
  OS_USERNAME="${OS_USERNAME:-admin}" \
  OS_PASSWORD="${OS_PASSWORD:-password}" \
  OS_PROJECT_DOMAIN_NAME=default \
  openstack --debug ${@}
