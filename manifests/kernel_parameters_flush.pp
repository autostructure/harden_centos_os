#
class harden_centos_os::kernel_parameters_flush {
  # Flush kernel_parameters
  exec { '/sbin/sysctl -w net.ipv4.route.flush=1': }
  exec { '/sbin/sysctl -w net.ipv6.route.flush=1': }
}
