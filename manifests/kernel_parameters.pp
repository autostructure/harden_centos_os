#
class harden_centos_os::kernel_parameters {
  # Set kernel_parameters
  create_resources('sysctl', $::harden_centos_os::kernel_parameters)
}
