#
class harden_centos_os::post_fw {
  firewallchain { 'INPUT:filter:IPv4':
    ensure => present,
    policy => drop,
  }

  firewallchain { 'OUTPUT:filter:IPv4':
    ensure => present,
    policy => drop,
  }

  firewallchain { 'FORWARD:filter:IPv4':
    ensure => present,
    policy => drop,
  }
}
