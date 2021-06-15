#!/bin/bash -e

case "$(uname -m)" in
  x86_64)  SYS_ARCH=amd64;;
  aarch64) SYS_ARCH=arm64;;
  *) kubedee::exit_error "Unsupported architecture.";;
esac

LXD_NETWORK_PREFIX="${LXD_NETWORK_PREFIX:-rke}"
LXD_NETWORK="${LXD_NETWORK_PREFIX}-$(tr -cd 'a-z0-9' </dev/urandom | head -c 4 ||:)"
lxc network show "${LXD_NETWORK}" &>/dev/null || lxc network create "${LXD_NETWORK}" ipv6.address=none

CONTROLS="${CONTROLS:-3}" WORKERS="${WORKERS:-1}"
USERNAME="${USERNAME:-user}" USERPASS="${USERPASS:-asdf}"
LXD_IMAGE="${LXD_IMAGE:-rke-node}"

read -r -d '' raw_lxc <<RAW_LXC ||:
lxc.apparmor.profile=unconfined
lxc.mount.auto=proc:rw sys:rw cgroup:rw
lxc.init.cmd=/sbin/init systemd.unified_cgroup_hierarchy=0
lxc.cgroup.devices.allow=a
lxc.cap.drop=
lxc.apparmor.allow_incomplete=1
RAW_LXC

LXD_INIT_ARGS=(
  "-c security.secureboot=false"
  "-c limits.cpu=$(nproc)"
  "-c limits.memory=${LXD_MEMORY_LIMIT:-4GiB}"
  "-c security.privileged=true"
  "-c security.nesting=true"
  "-c linux.kernel_modules=ip_tables,ip6_tables,netlink_diag,nf_nat,overlay,kvm,vhost-net,vhost-scsi,vhost-vsock,vsock"
)

if ! lxc image info "${LXD_IMAGE}" &>/dev/null; then
  BUILDER_ID="rke-setup-$(tr -cd 'a-z0-9' </dev/urandom | head -c 4 ||:)"
  lxc init ${LXD_INIT_ARGS[@]} \
    -c raw.lxc="${raw_lxc}" \
    "images:opensuse/tumbleweed/${SYS_ARCH}" "${BUILDER_ID}"
  lxc config device set "${BUILDER_ID}" root size="${LXD_ROOTFS_SIZE:-20GiB}" ||:
  lxc network attach "${LXD_NETWORK}" "${BUILDER_ID}" eth0 eth0
  lxc start "${BUILDER_ID}"
  until lxc exec "${BUILDER_ID}" -- ping -c1 -w1 google.com &>/dev/null; do sleep 1; done
  lxc exec "${BUILDER_ID}" -- /bin/bash -e ${SCRIPT_DEBUG:+-x} <<EOF
zypper up -ly
zypper in -ly docker openssh
mkdir -p /etc/systemd/system/docker.service.d
cat <<EOD >/etc/systemd/system/docker.service.d/mounts.conf
[Service]
MountFlags=rshared
EOD
echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config
useradd -ms /bin/bash "${USERNAME}"
echo -ne "${USERPASS}\\n${USERPASS}" | passwd "${USERNAME}"
usermod -aG docker "${USERNAME}"
systemctl enable docker sshd --now
sysctl -w net.bridge.bridge-nf-call-iptables=1
EOF
  lxc stop "${BUILDER_ID}"
  lxc snapshot "${BUILDER_ID}" snap
  lxc publish "${BUILDER_ID}/snap" --alias "${LXD_IMAGE}"
  lxc delete -f "${BUILDER_ID}" || lxc network detach "${LXD_NETWORK}" "${BUILDER_ID}"
fi

RKE_SSH_KEY="$(mktemp)"
rm "${RKE_SSH_KEY}"
ssh-keygen -N '' -f "${RKE_SSH_KEY}"

for i in $(seq $((${CONTROLS}+${WORKERS}))); do
  INSTANCE_ID="${LXD_NETWORK}-$(tr -cd 'a-z0-9' </dev/urandom | head -c 4 ||:)"
  lxc init ${LXD_INIT_ARGS[@]} \
    -c raw.lxc="${raw_lxc}" \
    "${LXD_IMAGE}" "${INSTANCE_ID}"
  lxc network attach "${LXD_NETWORK}" "${INSTANCE_ID}" eth0 eth0
  lxc config device add "${INSTANCE_ID}" "kmsg" unix-char source="/dev/kmsg" path="/dev/kmsg"
  lxc config device add "${INSTANCE_ID}" "kvm" unix-char source="/dev/kvm" path="/dev/kvm"
  lxc config device add "${INSTANCE_ID}" "net-tun" unix-char source="/dev/net/tun" path="/dev/net/tun"
  lxc config device add "${INSTANCE_ID}" "vhost-net" unix-char source="/dev/vhost-net" path="/dev/vhost-net"
  lxc config device add "${INSTANCE_ID}" "vhost-scsi" unix-char source="/dev/vhost-scsi" path="/dev/vhost-sci"
  lxc config device add "${INSTANCE_ID}" "vhost-vsock" unix-char source="/dev/vhost-vsock" path="/dev/vhost-vsock"
  lxc config device add "${INSTANCE_ID}" "vsock" unix-char source="/dev/vsock" path="/dev/vsock"

  lxc file push -p "${RKE_SSH_KEY}.pub" "${INSTANCE_ID}/home/${USERNAME}/.ssh/authorized_keys"

  lxc start "${INSTANCE_ID}"
  lxc exec "${INSTANCE_ID}" -- mount --make-shared /
  lxc exec "${INSTANCE_ID}" -- /bin/bash -e ${SHELL_DEBUG} <<EOF
chmod -R go-rwx "/home/${USERNAME}/.ssh"
chmod -R u+rw "/home/${USERNAME}/.ssh"
EOF
done

for i in $(lxc ls -f json | jq -r ".[] | select(.name|test(\"^${LXD_NETWORK}-\")).state.network | to_entries[] | select(.key|test(\"^(lo|docker)\")|not).value.addresses[] | select(.family==\"inet\").address"); do
  #ssh -i "${RKE_SSH_KEY}" "${USERNAME}@${i}" sudo mount --make-shared /
  until ssh -i "${RKE_SSH_KEY}" "${USERNAME}@${i}" echo; do sleep 1; done
done

#lxc ls -cn4 -f csv | awk -F, "/^${LXD_NETWORK}-/ {print \$2}"
echo "${RKE_SSH_KEY}"
