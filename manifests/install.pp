#
class harden_centos_os::install {
  # Enforce basic packag rules
  create_resources('package', $::harden_centos_os::managed_packages)

  # Install necessary kernel modules
  create_resources('kmod::install', $::harden_centos_os::kernel_module_installs)

  # Install necessary file_line rules
  create_resources('file_line', $::harden_centos_os::file_line_rules)

  # Add aide rules
  create_resources('aide::rule', $::harden_centos_os::aide_rules)

  # Set gpgcheck on yum.conf
  augeas { 'yum_gpgcheck':
    context => '/files/etc/yum.conf/main',
    changes => [
      'set gpgcheck 1',
    ],
  }

  # Set gpgcheck on yum repositories
  # TODO
  $facts['yum_repos'].each | Integer $index, String $directory | {
    augeas { "${index}_gpgcheck":
      context => "/files${directory}/main",
      changes => [
        'setm /files/etc/yum.repos.d/CentOS-Sources.repo/*[label() =~ regexp(\'^[^#]+\')] gpgcheck 1',
      ],
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
