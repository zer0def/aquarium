#!/bin/sh -ex

kubedee/kubedee \
  --apiserver-extra-hostnames "kubernetes.default,kubernetes.default.svc,kubernetes.default.svc.cluster.local" \
  --kubernetes-version "v${K8S_VERSION:-1.21.1}" \
  --storage-pool "${LXD_STORAGE_POOL:-default}" \
  --num-worker "${NUM_WORKERS:-1}" \
  --enable-insecure-registry \
  up "${CLUSTER_NAME:-asdf}"
