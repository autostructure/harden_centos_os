#
class harden_centos_os::configure {
  # Enforce file and directory rules
  create_resources('file', $::harden_centos_os::managed_files)
}
