#
class harden_centos_os::run {
  # Mange the services
  create_resources('service', $::harden_centos_os::managed_services)
}
