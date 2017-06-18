#
class harden_centos_os::post_fw {
  firewallchain { 'INPUT:filter:IPv4':
    ensure => present,
    policy => drop,
    before => undef,
  }

  firewallchain { 'OUTPUT:filter:IPv4':
    ensure => present,
    policy => drop,
    before => undef,
  }

  firewallchain { 'FORWARD:filter:IPv4':
    ensure => present,
    policy => drop,
    before => undef,
  }
}
