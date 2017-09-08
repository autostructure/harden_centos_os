#
class harden_centos_os::run {
  # Mange the services
  # $::harden_centos_os::managed_services.each | String $key, Hash $values | {
  #   service { $key:
  #     ensure => $values['ensure'],
  #     enable => $values['enable'],
  #   }
#
  #   $service = @("CODE"/$)
#
  #       if(\$ensure_${key}_services_are_not_enabled) {
  #         service { '${key}':
  #           ensure => ${values['ensure']},
  #           enable => ${values['enable']},
  #         }
  #       }
  #     | CODE
#
  #   notify { $service: }
  # }

  if($harden_centos_os::ensure_ldap_server_is_not_enabled) {
    service { 'slapd':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_nfs_and_rpc_are_not_enabled) {
    service { 'nfs':
      ensure => stopped,
      enable => false,
    }

    service { 'rpcbind':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_dns_server_is_not_enabled) {
    service { 'named':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_ftp_server_is_not_enabled) {
    service { 'vsftpd':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_http_server_is_not_enabled) {
    service { 'httpd':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_imap_and_pop3_server_is_not_enabled) {
    service { 'dovecot':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_samba_is_not_enabled) {
    service { 'smb':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_http_proxy_server_is_not_enabled) {
    service { 'squid':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_snmp_server_is_not_enabled) {
    service { 'snmpd':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_nis_server_is_not_enabled) {
    service { 'ypserv':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_rsh_server_is_not_enabled) {
    service { 'rsh.socket':
      ensure => stopped,
      enable => false,
    }

    service { 'rlogin.socket':
      ensure => stopped,
      enable => false,
    }

    service { 'rexec.socket':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_telnet_server_is_not_enabled) {
    service { 'telnet.socket':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_tftp_server_is_not_enabled) {
    service { 'tftp.socket':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_rsync_service_is_not_enabled) {
    service { 'rsyncd':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_talk_server_is_not_enabled) {
    service { 'ntalk':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::disable_automounting) {
    service { 'autofs':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_chargen_services_are_not_enabled) {
    service { 'chargen-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'chargen-stream':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_daytime_services_are_not_enabled) {
    service { 'daytime-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'daytime-stream':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_discard_dgram_services_are_not_enabled) {
    service { 'discard-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'discard-stream':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_echo_services_are_not_enabled) {
    service { 'echo-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'echo-stream':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_time_services_are_not_enabled) {
    service { 'time-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'time-stream':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_tftp_services_are_not_enabled) {
    service { 'tftp':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_xinetd_services_are_not_enabled) {
    service { 'xinetd':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_avahi_server_is_not_enabled) {
    service { 'avahi-daemon':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_cups_services_are_not_enabled) {
    service { 'cups':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_dhcpd_services_are_not_enabled) {
    service { 'dhcpd':
      ensure => stopped,
      enable => false,
    }
  }

  if($harden_centos_os::ensure_postfix_services_are_not_enabled) {
    service { 'postfix':
      ensure => running,
    }
  }
}
