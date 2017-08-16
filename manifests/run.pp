#
class harden_centos_os::run {
  # Mange the services
  $::harden_centos_os::managed_services.each | String $key, Hash $values | {
    service { $key:
      ensure => $values['ensure'],
      enable => $values['enable'],
    }
  }
}
