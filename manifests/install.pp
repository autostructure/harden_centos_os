#
class harden_centos_os::install {

  # Ensure message of the day is configured properly
  $clean_motd = regsubst($::harden_centos_os::motd, '(\\v|\\r|\\m|\\s)', '')

  # Ensure permissions on /etc/motd are configured
  file { '/etc/motd':
    ensure  => file,
    content => $clean_motd,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }

  # Ensure local login warning banner is configured properly
  $clean_issue = regsubst($::harden_centos_os::issue, '(\\v|\\r|\\m|\\s)', '')

  # Ensure permissions on /etc/issue are configured
  file { '/etc/issue':
    ensure  => file,
    content => $clean_issue,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }

  # Ensure permissions on /etc/issue.net are configured
  file { '/etc/issue.net':
    ensure  => file,
    content => $clean_issue,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }

  # Enforce basic package rules
  $::harden_centos_os::managed_packages.each | String $key, Hash $values | {
    package { $key:
      ensure => $values['ensure'],
    }
  }

  # Install necessary kernel modules
  $::harden_centos_os::kernel_module_installs.each | String $key, Hash $values | {
    kmod::install { $key:
      command => $values['command'],
    }
  }

  # Install necessary kernel modules
  $::harden_centos_os::kernel_module_options.each | String $key, Hash $values | {
    kmod::option { $key:
      option => $values['command'],
      value  => $values['value'],
    }
  }

  # Add aide rules
  $::harden_centos_os::aide_rules.each | String $key, Hash $values | {
    aide::rule { $key:
      content => $values['content'],
    }
  }

  # Add limits rules
  $::harden_centos_os::limits.each | String $key, Hash $values | {
    limits::fragment { $key:
      value => $values['value'],
    }
  }

  # Run rsyslog
  include ::rsyslog::client

  # Enforce sshd rules
  class { '::ssh':
    permit_root_login                 => $harden_centos_os::sshd_configs['permit_root_login'],
    sshd_config_loglevel              => $harden_centos_os::sshd_configs['sshd_config_loglevel'],
    sshd_config_permitemptypasswords  => $harden_centos_os::sshd_configs['sshd_config_permitemptypasswords'],
    sshd_config_permituserenvironment => $harden_centos_os::sshd_configs['sshd_config_permituserenvironment'],
    sshd_config_login_grace_time      => $harden_centos_os::sshd_configs['sshd_config_login_grace_time'],
    sshd_config_ciphers               => $harden_centos_os::sshd_configs['sshd_config_ciphers'],
    sshd_config_macs                  => $harden_centos_os::sshd_configs['sshd_config_macs'],
    sshd_config_allowgroups           => $harden_centos_os::sshd_configs['sshd_config_allowgroups'],
    sshd_config_allowusers            => $harden_centos_os::sshd_configs['sshd_config_allowusers'],
    sshd_config_denygroups            => $harden_centos_os::sshd_configs['sshd_config_denygroups'],
    sshd_config_denyusers             => $harden_centos_os::sshd_configs['sshd_config_denyusers'],
    sshd_config_maxauthtries          => $harden_centos_os::sshd_configs['sshd_config_maxauthtries'],
    sshd_config_banner                => $harden_centos_os::sshd_configs['sshd_config_banner'],
    sshd_client_alive_count_max       => $harden_centos_os::sshd_configs['sshd_client_alive_count_max'],
    sshd_client_alive_interval        => $harden_centos_os::sshd_configs['sshd_client_alive_interval'],
    sshd_hostbasedauthentication      => $harden_centos_os::sshd_configs['sshd_hostbasedauthentication'],
    sshd_ignorerhosts                 => $harden_centos_os::sshd_configs['sshd_ignorerhosts'],
    sshd_config_owner                 => $harden_centos_os::sshd_configs['sshd_config_owner'],
    sshd_config_group                 => $harden_centos_os::sshd_configs['sshd_config_group'],
    sshd_config_mode                  => $harden_centos_os::sshd_configs['sshd_config_mode'],
  }
}
