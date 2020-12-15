# Rookery - Openstack+Ceph-on-K8S dev environment on LXD VMs via Kubedee

### Usage

```
rookery - Openstack+Ceph-on-K8S dev environment on LXD VMs via Kubedee

Usage: rookery/rookery.sh [options] <up|down>

Options:
  -N <name>, --name <name>             cluster name
                                       (default: rookery, env: CLUSTER_NAME)
  -n <num>, --num <num>                number of workers
                                       (default: 1, env: NUM_WORKERS)
  -V <tag>, --tag <tag>                Kubernetes version to use
                                       (default: 1.20.1, env: K8S_VERSION)
  -s <pool>, --storage-pool <pool>     LXD storage pool to use for the K8S cluster
                                       (default: default, env: LXD_STORAGE_POOL)
  -o <tag>, --openstack-version <tag>  Openstack version to deploy
                                       (default: victoria, env: OS_VERSION)
  -b <base>, --base-image <base>       base LOCI image to use for Openstack
                                       images (default: ubuntu_bionic, env: BASE_IMAGE)
  -c <mem>, --controller-mem <mem>     memory to allocate towards K8S controller
                                       (default: 2GiB, env: CONTROLLER_MEMORY_SIZE)
  -w <mem>, --worker-mem <mem>         memory to allocate per K8S worker
                                       (default: 12GiB, env: WORKER_MEMORY_SIZE)
```

### Requirements

- ~2GiB of memory for the K8S controller
- ~10GiB of memory to just launch all expected components as single nodes on a single K8S worker node (which is why it defaults to 12GiB with a memballoon, so it's able to fit on a 16GiB machine)

### Project status

I'm amazed it actually kind of works. Take this at face value.
