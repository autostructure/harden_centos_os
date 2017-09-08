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


  if($harden_centos_os::ensure_core_dumps_are_restricted) {
    sysctl { 'fs.suid_dumpable':
      value => 0,
    }
  }

  if($harden_centos_os::ensure_address_space_layout_randomization_aslr_is_enabled) {
    sysctl { 'kernel.randomize_va_space':
      value => 2,
    }
  }

  if($harden_centos_os::ensure_ip_forwarding_is_disabled) {
    sysctl { 'net.ipv4.ip_forward':
      value => 0,
    }
  }

  if($harden_centos_os::ensure_packet_redirect_sending_is_disabled) {
    sysctl { 'net.ipv4.conf.all.send_redirects':
      value => 0,
    }

    sysctl { 'net.ipv4.conf.default.send_redirects':
      value => 0,
    }
  }

  if($harden_centos_os::ensure_source_routed_packets_are_not_accepted) {
    sysctl { 'net.ipv4.conf.all.accept_source_route':
      value => 0,
    }

    sysctl { 'net.ipv4.conf.default.accept_source_route':
      value => 0,
    }
  }

  if($harden_centos_os::ensure_icmp_redirects_are_not_accepted) {
    sysctl { 'net.ipv4.conf.all.accept_redirects':
      value => 0,
    }

    sysctl { 'net.ipv4.conf.default.accept_redirects':
      value => 0,
    }
  }

  if($harden_centos_os::ensure_secure_icmp_redirects_are_not_accepted) {
    sysctl { 'net.ipv4.conf.all.secure_redirects':
      value => 0,
    }

    sysctl { 'net.ipv4.conf.default.secure_redirects':
      value => 0,
    }
  }

  if($harden_centos_os::ensure_suspicious_packets_are_logged) {
    sysctl { 'net.ipv4.conf.all.log_martians':
      value => 1,
    }

    sysctl { 'net.ipv4.conf.default.log_martians':
      value => 1,
    }
  }

  if($harden_centos_os::ensure_broadcast_icmp_requests_are_ignored) {
    sysctl { 'net.ipv4.icmp_echo_ignore_broadcasts':
      value => 1,
    }
  }

  if($harden_centos_os::ensure_bogus_icmp_responses_are_ignored) {
    sysctl { 'net.ipv4.icmp_ignore_bogus_error_responses':
      value => 1,
    }
  }

  if($harden_centos_os::ensure_reverse_path_filtering_is_enabled) {
    sysctl { 'net.ipv4.conf.all.rp_filter':
      value => 1,
    }

    sysctl { 'net.ipv4.conf.default.rp_filter':
      value => 1,
    }
  }

  if($harden_centos_os::ensure_tcp_syn_cookies_is_enabled) {
    sysctl { 'net.ipv4.tcp_syncookies':
      value => 1,
    }
  }

  if($harden_centos_os::ensure_ipv6_router_advertisements_are_not_accepted) {
    sysctl { 'net.ipv6.conf.all.accept_ra':
      value => 0,
    }

    sysctl { 'net.ipv6.conf.default.accept_ra':
      value => 0,
    }
  }

  if($harden_centos_os::ensure_ipv6_redirects_are_not_accepted) {
    sysctl { 'net.ipv6.conf.all.accept_redirects':
      value => 0,
    }

    sysctl { 'net.ipv6.conf.default.accept_redirects':
      value => 0,
    }
  }

  # Set kernel_parameters
  # $::harden_centos_os::kernel_parameters.each | String $key, Hash $values | {
  #   sysctl { $key:
  #     ensure => $values['ensure'],
  #     value  => $values['value'],
  #   }
#
  #   $sysctl = @("CODE"/L)
#
  #       if(x) {
  #         sysctl { ${key}:
  #           ensure => ${values}['ensure'],
  #           value  => ${values}['value'],
  #         }
  #       }
  #     | CODE
#
  #   notify { $sysctl: }
  # }


  if($harden_centos_os::ensure_aide_is_installed) {
    package { 'aide':
      ensure => installed,
    }
  }

  if($harden_centos_os::ensure_prelink_is_disabled) {
    package { 'prelink':
      ensure => absent,
    }
  }

  if($harden_centos_os::ensure_setroubleshoot_is_not_installed) {
    package { 'setroubleshoot':
      ensure => absent,
    }
  }

  if($harden_centos_os::ensure_the_mcs_translation_service_is_not_installed) {
    package { 'mcstrans':
      ensure => absent,
    }
  }

  if($harden_centos_os::ensure_nis_client_is_not_installed) {
    package { 'ypbind':
      ensure => absent,
    }
  }

  if($harden_centos_os::ensure_rsh_client_is_not_installed) {
    package { 'rsh':
      ensure => absent,
    }
  }

  if($harden_centos_os::ensure_talk_client_is_not_installed) {
    package { 'talk':
      ensure => absent,
    }
  }

  if($harden_centos_os::ensure_telnet_client_is_not_installed) {
    package { 'telnet':
      ensure => absent,
    }
  }

  if($harden_centos_os::ensure_ldap_client_is_not_installed) {
    package { 'openldap-clients':
      ensure => absent,
    }
  }

  if($harden_centos_os::ensure_tcp_wrappers_is_installed) {
    package { 'tcp_wrappers':
      ensure => installed,
    }
  }

  # Enforce basic package rules
  # $::harden_centos_os::managed_packages.each | String $key, Hash $values | {
  #   package { $key:
  #     ensure => $values['ensure'],
  #   }
#
  #   $package = @("CODE"/$)
#
  #       if(\$ensure_${key}_is_${values['ensure']}) {
  #         package { '${key}':
  #           ensure => ${values['ensure']},
  #         }
  #       }
  #     | CODE
#
  #   notify { $package: }
  # }


  if($harden_centos_os::ensure_mounting_of_cramfs_filesystems_is_disabled) {
    kmod::install { 'cramfs':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_mounting_of_freevxfs_filesystems_is_disabled) {
    kmod::install { 'freevxfs':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_mounting_of_jffs2_filesystems_is_disabled) {
    kmod::install { 'jffs2':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_mounting_of_hfs_filesystems_is_disabled) {
    kmod::install { 'hfs':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_mounting_of_hfsplus_filesystems_is_disabled) {
    kmod::install { 'hfsplus':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_mounting_of_squashfs_filesystems_is_disabled) {
    kmod::install { 'squashfs':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_mounting_of_udf_filesystems_is_disabled) {
    kmod::install { 'udf':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_mounting_of_fat_filesystems_is_disabled) {
    kmod::install { 'vfat':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_dccp_is_disabled) {
    kmod::install { 'dccp':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_sctp_is_disabled) {
    kmod::install { 'sctp':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_rds_is_disabled) {
    kmod::install { 'rds':
      command => '/bin/true',
    }
  }

  if($harden_centos_os::ensure_tipc_is_disabled) {
    kmod::install { 'tipc':
      command => '/bin/true',
    }
  }

  # Install necessary kernel modules
  # $::harden_centos_os::kernel_module_installs.each | String $key, Hash $values | {
  #   kmod::install { $key:
  #     command => $values['command'],
  #   }
#
  #   $kmod = @("CODE"/$)
#
  #       if(\$ensure_mounting_of_${key}_filesystem_is_disabled) {
  #         kmod::install { '${key}':
  #           command => ${values['command']},
  #         }
  #       }
  #     | CODE
#
  #   notify { $kmod: }
  # }


  if($harden_centos_os::ensure_ipv6_is_disabled) {
    kmod::option { 'ipv6':
      option => disable,
      value  => 1,
    }
  }

  # Install necessary kernel modules
  # $::harden_centos_os::kernel_module_options.each | String $key, Hash $values | {
  #   kmod::option { $key:
  #     option => $values['command'],
  #     value  => $values['value'],
  #   }
#
  #   $kmod = @("CODE"/$)
#
  #       if(\$ensure_${key}_is_disabled) {
  #         kmod::option { '${key}':
  #           option => ${values['option']},
  #           value  => ${values['value']},
  #         }
  #       }
  #     | CODE
#
  #   notify { $kmod: }
  # }

  # Add aide rules
  # $::harden_centos_os::aide_rules.each | String $key, Hash $values | {
  #   aide::rule { $key:
  #     content => $values['content'],
  #   }
  # }


  if($harden_centos_os::ensure_core_dumps_are_restricted) {
    limits::fragment { '*/hard/core':
      value => 0,
    }
  }

  # Add limits rules
  # $::harden_centos_os::limits.each | String $key, Hash $values | {
  #   limits::fragment { $key:
  #     value => $values['value'],
  #   }
#
  #   $limit = @("CODE"/$)
#
  #       if(\$ensure_${key}_are_restricted) {
  #         limits::fragment { '${key}':
  #           value  => ${values['value']},
  #         }
  #       }
  #     | CODE
#
  #   notify { $limit: }
  # }

  # Run rsyslog
  include ::rsyslog::client

  $permit_root_login = $harden_centos_os::ensure_ssh_root_login_is_disabled ? {
    true => 'no',
    default => undef,
  }

  $sshd_x11_forwarding = $harden_centos_os::ensure_ssh_x11_forwarding_is_disabled ? {
    true => 'no',
    default => undef,
  }

  $sshd_config_permitemptypasswords = $harden_centos_os::ensure_ssh_permitemptypasswords_is_disabled ? {
    true => 'no',
    default => undef,
  }

  $sshd_config_loglevel = $harden_centos_os::sshd_config_loglevel ? {
    true => 'INFO',
    default => undef,
  }

  $sshd_hostbasedauthentication = $harden_centos_os::ensure_ssh_hostbasedauthentication_is_disabled ? {
    true => 'no',
    default => undef,
  }

  $sshd_ignorerhosts = $harden_centos_os::ensure_ssh_ignorerhosts_is_enabled ? {
    true => 'yes',
    default => undef,
  }

  $sshd_config_permituserenvironment = $harden_centos_os::ensure_ssh_permituserenvironment_is_disabled ? {
    true => 'no',
    default => undef,
  }

  $sshd_config_maxauthtries = $harden_centos_os::ensure_ssh_maxauthtries_is_set_to_4_or_less ? {
    true => min(4, undef),
    default => undef,
  }

  $sshd_config_login_grace_time = $harden_centos_os::ensure_ssh_logingracetime_is_set_to_one_minute_or_less ? {
    true => min(60, undef),
    default => undef,
  }

  case $harden_centos_os::ensure_permissions_on__etc_ssh_sshd_config_are_configured {
    true: {
      $sshd_config_owner = 'root'
      $sshd_config_group = 'root'
      $sshd_config_mode  = 'og-rwx'
    }
    default: {
      $sshd_config_owner = undef
      $sshd_config_group = undef
      $sshd_config_mode  = undef
    }
  }

  $sshd_config_ciphers = $harden_centos_os::ensure_only_approved_ciphers_are_used ? {
    true => [
      'aes256-ctr',
      'aes192-ctr',
      'aes128-ctr',
    ],
    default => undef,
  }

  $sshd_config_macs = $harden_centos_os::ensure_only_approved_mac_algorithms_are_used ? {
    true => [
      'hmac-sha2-512-etm@openssh.com',
      'hmac-sha2-256-etm@openssh.com',
      'umac-128-etm@openssh.com',
      'hmac-sha2-512',
      'hmac-sha2-256',
      'umac-128@openssh.com',
    ],
    default => undef,
  }

  # Enforce sshd rules
  class { '::ssh':
    permit_root_login                 => $permit_root_login,
    sshd_x11_forwarding               => $sshd_x11_forwarding,
    sshd_config_loglevel              => $sshd_config_loglevel,
    sshd_config_permitemptypasswords  => $sshd_config_permitemptypasswords,
    sshd_config_permituserenvironment => $sshd_config_permituserenvironment,
    sshd_config_login_grace_time      => $sshd_config_login_grace_time,
    sshd_config_ciphers               => $sshd_config_ciphers,
    sshd_config_macs                  => $sshd_config_macs,
    sshd_config_allowgroups           => $harden_centos_os::sshd_config_allowgroups,
    sshd_config_allowusers            => $harden_centos_os::sshd_config_allowusers,
    sshd_config_denygroups            => $harden_centos_os::sshd_config_denygroups,
    sshd_config_denyusers             => $harden_centos_os::sshd_config_denyusers,
    sshd_config_maxauthtries          => $sshd_config_maxauthtries,
    sshd_config_banner                => $harden_centos_os::sshd_config_banner,
    sshd_client_alive_count_max       => $harden_centos_os::sshd_client_alive_count_max,
    sshd_client_alive_interval        => $harden_centos_os::sshd_client_alive_interval,
    sshd_hostbasedauthentication      => $sshd_hostbasedauthentication,
    sshd_ignorerhosts                 => $sshd_ignorerhosts,
    sshd_config_owner                 => $sshd_config_owner,
    sshd_config_group                 => $sshd_config_group,
    sshd_config_mode                  => $sshd_config_mode,
  }
}
