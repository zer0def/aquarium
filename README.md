# Aquarium - highly-opinionated Linux-centric scaffold for local multi-node Kubernetes development

## Summary

Aquarium's design goal is to leverage Docker (using k3s/k3d) or LXD (using proper Kubernetes through Kubedee) to provide a comparatively lightweight scaffold for launching multi-node Kubernetes development environments on your local machine, while trying to address some of a pain points of doing so.

Most notably, this project tries really hard to avoid using operators where they're not necessary, as they usually serve as means to upsell the user on a product, while funnelling away from otherwise perfectly available configuration options and into each respective party's walled garden to gauge for.

### Usage

```
aquarium - Linux-centric scaffold for local K8S development

Usage: aquarium.sh [options] <up|down>

Options:
  --no-*, --with-*                    disable/enable installation of selected
                                      component (choice of: registry-proxy,
                                        monitoring, serverless, service-mesh,
                                        storage, local-registry,
                                        env: non-zero value on INSTALL_*)
  -N <name>, --name <name>            cluster name (default: k3s-default,
                                        env: CLUSTER_NAME)
  -n <num>, --num <num>               number of workers (default: `nproc`/4,
                                        env: NUM_WORKERS)
  -r <runtime>, --runtime <runtime>   runtime choice (default: k3d,
                                        choice of: k3d, kubedee,
                                        env: K8S_RUNTIME)
  -t <tag>, --tag <tag>               set runtime version (env: RUNTIME_TAG)
  -s <pool>, --storage-pool <pool>    LXD storage pool to use with Kubedee
                                        (default: default,
                                        env: LXD_STORAGE_POOL)
  --vm                                launch cluster in LXD VMs, instead of LXD
                                        containers (requires `-r kubedee`)
  -c <mem>, --controller-mem <mem>    memory to allocate towards K8S controller
                                        (requires `--vm`, default: 2GiB,
                                        env: CONTROLLER_MEMORY_SIZE)
  -w <mem>, --worker-mem <mem>        memory to allocate per K8S worker
                                        (requires `--vm`, default: 4GiB,
                                        env: WORKER_MEMORY_SIZE)
  -R <size>, --rootfs-size <size>     build rootfs image of provided size
                                        (requires `--vm`, default: 20GiB,
                                        env: ROOTFS_SIZE)

Environment variables:

  Registry proxy (ref: https://github.com/rpardini/docker-registry-proxy#usage ):
    PROXY_REGISTRIES    space-delimited string listing registry domains to cache
                        OCI image layers from
    AUTH_REGISTRIES     space-delimited string listing "domain:username:password"
                        information for the proxy to authenticate to registries
```

### Project status

Highly bug-riddled alpha, YMMV. You probably should skim through, before using. You have been warned.

### Project rationale

#### Resource usage

Other solutions targeted for Kubernetes development (taking Minikube & friends as an example) can be resource-taxing due to hypervisor overhead, which this avoids through usage of OCI/system containers. For Windows and MacOS X users, in terms of memory, that potentially means packing more into their Hyper-V/xhyve Docker VM or WSL-based VM, than Minikube or Docker-packaged Kubernetes might, though at possible cost of added CPU overhead, since those are still hypervised.

#### Don't fight your tools when you don't need to

Even with constant various improvements in upstream projects, over the years there has been a number of barely-addressed crippling corner cases, solutions to some of which have rotten away in experimental branches before eventually getting upstreamed after everyone has abandoned them by virtue of not wanting to endlessly fight the tools they need.

#### Emulate your target environment without development/provider-specific cruft

There's also an issue of developing (and, perhaps more importantly, adequately testing) Kubernetes manifests for things like solution resilience or scalability, which you cannot properly do on a single-node environment without making development-specific additions/exceptions to your manifests. This allows you to focus on your goal, not how to make it work within artificial constraints, most of the time.

## Dependencies

Binaries/scripts (but not OCI images or Helm charts) listed below are expected to be in your system's `PATH`.

### Hard dependencies

- Docker
- kubectl
- [Helm](https://github.com/helm/helm)
- [Helmfile](https://github.com/roboll/helmfile)
- either of:
    - [k3d](https://github.com/rancher/k3d)
    - [kubedee](https://github.com/schu/kubedee) (along with [cfssl](https://github.com/cloudflare/cfssl), [jq](https://github.com/stedolan/jq) and [lxd](https://github.com/lxc/lxd))

### Optional dependencies (enabled by default!)

- [docker-volume-loopback](https://github.com/ashald/docker-volume-loopback) (when Docker root is running on a filesystem not supporting overlays)
- [docker-registry-proxy](https://github.com/rpardini/docker-registry-proxy) (transparent proxy for caching OCI image layers)
- [Kata Containers](https://github.com/kata-containers/kata-containers)

### Charts/software used, depending on component selection

Logical components are split into namespaces according to the following logic:

- storage:
  - [External-Secrets](https://github.com/external-secrets/external-secrets)
  - [OpenEBS](https://github.com/openebs/openebs) in local volume provisioner mode
  - [SeaweedFS](https://github.com/chrislu/seaweedfs) for object storage (MinIO replacement)
  - [Patroni](https://github.com/zalando/patroni)/[Spilo](https://github.com/zalando/spilo) for PostgreSQL deployment
  - [RedPanda](https://github.com/redpanda-data/redpanda) (Kafka replacement)
  - [KeyDB](https://github.com/snapchat/keydb) (Redis replacement)
  - [Scylla](https://github.com/scylladb/scylladb) (Cassandra replacement)
- network/service mesh: [Istio](https://github.com/istio/istio)
- monitoring:
  - [Loki](https://github.com/grafana/loki)
  - [OpenSearch](https://github.com/opensearch-project/OpenSearch)
  - [Prometheus-Operator](https://github.com/coreos/prometheus-operator) with [Thanos](https://github.com/thanos-io/thanos) or [Cortex](https://github.com/cortexproject/cortex)
- serverless: [OpenFAAS](https://docs.openfaas.com/), possibly [Fission](https://github.com/fission/fission)
- development:
  - [GitLab](https://gitlab.com/gitlab-org/gitlab)
  - [Harbor](https://github.com/goharbor/harbor) for cluster-local registry
  - [Sentry](https://github.com/getsentry/self-hosted)
  - [Zulip](https://github.com/zulip/zulip)

## Known issues

- Kata's available only through Kubedee
- Kubedee: Registry proxy not deployed as an LXD container, making Docker a harder dependency than it genuinely needs to be
- most likely inconsistent whitespace handling, deal with it

## Legalese

Reality says "put it under WTFPL", but sure, let's try LGPL3.
