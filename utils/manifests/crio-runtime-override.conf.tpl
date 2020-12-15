[crio.runtime]
manage_network_ns_lifecycle = true
manage_ns_lifecycle = true

[crio.runtime.runtimes.kata-qemu]
privileged_without_host_devices = true
runtime_path = "${RUNTIMES_ROOT}/bin/containerd-shim-kata-v2"
runtime_type = "vm"
#runtime_path = "${RUNTIMES_ROOT}/bin/kata-runtime"
#runtime_type = "oci"

[crio.runtime.runtimes.kata-fc]
privileged_without_host_devices = true
runtime_path = "${RUNTIMES_ROOT}/bin/containerd-shim-kata-v2"
runtime_type = "vm"
#runtime_path = "${RUNTIMES_ROOT}/bin/kata-runtime"
#runtime_type = "oci"

[crio.runtime.runtimes.kata-clh]
privileged_without_host_devices = true
runtime_path = "${RUNTIMES_ROOT}/bin/containerd-shim-kata-v2"
runtime_type = "vm"
#runtime_path = "${RUNTIMES_ROOT}/bin/kata-runtime"
#runtime_type = "oci"
