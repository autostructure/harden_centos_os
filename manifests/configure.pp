#
class harden_centos_os::configure {


  if($harden_centos_os::ensure__etc_hosts_allow_is_configured) {
    file { '/etc/hosts.allow':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => "ALL: ${facts['network']}/${facts['netmask']}",
    }
  }

  if($harden_centos_os::ensure__etc_hosts_deny_is_configured) {
    file { '/etc/hosts.deny':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => 'ALL: ALL',
    }
  }

  # 5.1.2 Ensure permissions on /etc/crontab are configured
  if($harden_centos_os::ensure_permissions_on__etc_crontab_are_configured) {
    file { '/etc/crontab':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_cron_hourly_are_configured) {
    file { '/etc/cron_hourly':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_cron_daily_are_configured) {
    file { '/etc/cron_daily':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_cron_weekly_are_configured) {
    file { '/etc/cron_weekly':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_cron_monthly_are_configured) {
    file { '/etc/cron_monthly':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_cron_d_are_configured) {
    file { '/etc/cron_d':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  if($harden_centos_os::ensure_at_cron_is_restricted_to_authorized_users) {
    file { '/etc/cron_deny':
      ensure  => absent,
    }

    file { '/etc/at.deny':
      ensure  => absent,
    }

    file { '/etc/cron_allow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }

    file { '/etc/at.allow':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_passwd_are_configured) {
    file { '/etc/passwd':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_shadow_are_configured) {
    file { '/etc/shadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_group_are_configured) {
    file { '/etc/group':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_gshadow_are_configured) {
    file { '/etc/gshadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_passwd__are_configured) {
    file { '/etc/passwd_':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_shadow__are_configured) {
    file { '/etc/shadow-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_group__are_configured) {
    file { '/etc/group-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }

  if($harden_centos_os::ensure_permissions_on__etc_gshadow__are_configured) {
    file { '/etc/gshadow-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }

  if($harden_centos_os::ensure_permissions_on_bootloader_config_are_configured) {
    file { '/boot/grub2/grub.cfg':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  # Enforce file and directory rules
  #$::harden_centos_os::managed_files.each | String $key, Hash $value | {
  #  file { $key:
  #    ensure  => $value['ensure'],
  #    owner   => $value['owner'],
  #    group   => $value['group'],
  #    mode    => $value['mode'],
  #    content => $value['content'],
  #  }
#
  #  $file = @("CODE"/$)
#
  #      if(\$ensure_permissions_on_${key}_are_configured) {
  #        file { '${key}':
  #          ensure  => ${value['ensure']},
  #          owner   => ${value['owner']},
  #          group   => ${value['group']},
  #          mode    => ${value['mode']},
  #          content => ${value['content']},
  #        }
  #      }
  #    | CODE
#
  #  notify { $file: }
  #}


  if($harden_centos_os::ensure_default_user_umask_is_027_or_more_restrictive) {
    file_line { '/etc/bashrc_umask':
      ensure  => present,
      match   => '^umask',
      replace => true,
      path    => '/etc/bashrc',
      line    => 'umask \'027\'',
    }

    file_line { '/etc/profile_umask':
      ensure  => present,
      match   => '^umask',
      replace => true,
      path    => '/etc/profile',
      line    => 'umask \'027\'',
    }
  }

  if($harden_centos_os::ensure_authentication_required_for_single_user_mode) {
    file_line { 'rescue_service_sulogin':
      ensure  => present,
      match   => '^ExecStart=',
      replace => true,
      path    => '/usr/lib/systemd/system/rescue.service',
      line    => 'ExecStart=-/bin/sh -c \'/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\'',
    }

    file_line { 'emergency_service_sulogin':
      ensure  => present,
      match   => '^ExecStart=',
      replace => true,
      path    => '/usr/lib/systemd/system/emergency.service',
      line    => 'ExecStart=-/bin/sh -c \'/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\'',
    }
  }

  # Install necessary file_line rules
  # $::harden_centos_os::file_line_rules.each | String $key, Hash $values | {
  #   file_line { $key:
  #     ensure  => $values['ensure'],
  #     match   => $values['match'],
  #     replace => $values['replace'],
  #     path    => $values['path'],
  #     line    => $values['line'],
  #   }
#
  #   $file_line = @("CODE"/$)
#
  #       if(\$ensure_${key}_are_restricted) {
  #         file_line { '${key}':
  #           ensure  => ${values['ensure']},
  #           match   => ${values['match']},
  #           replace => ${values['replace']},
  #           path    => ${values['path']},
  #           line    => ${values['line']},
  #         }
  #       }
  #     | CODE
#
  #   notify { $file_line: }
  # }

  if($harden_centos_os::ensure_gpgcheck_is_globally_activated) {
    augeas { 'yum_gpgcheck':
      context => '/files/etc/yum.conf/main',
      changes => ['set gpgcheck 1'],
    }
  }

  if($harden_centos_os::ensure_mail_transfer_agent_is_configured_for_local_only_mode) {
    augeas { 'inet_interfaces':
      context => '/files/etc/postfix/main.cf',
      changes => ['set inet_interfaces localhost'],
    }
  }

  # Enforce augeas file rules
  # $::harden_centos_os::augeas_rules.each | String $key, Hash $values | {
  #   augeas { $key:
  #     context => $values['context'],
  #     changes => $values['changes'],
  #   }
#
  #   $augeas = @("CODE"/$)
#
  #       if(\$ensure_${key}_are_restricted) {
  #         augeas { '${key}':
  #           context => ${values['context']},
  #           changes => ${values['changes']},
  #         }
  #       }
  #     | CODE
#
  #   notify { $augeas: }
  # }

  # Set gpgcheck on yum repositories
  $facts['yum_repos'].each | Integer $index, String $file | {
    augeas { "${index}_gpgcheck":
      context => "/files${file}",
      changes => [
        'setm /*[label() =~ regexp(\'^[^#]+\')] gpgcheck 1',
      ],
    }
  }

  # Ensure permissions on all logfiles are configured
  $facts['log_files'].each | Integer $index, String $file | {
    file { $file:
      ensure => file,
      mode   => 'g-wx,o-rwx',
    }
  }

  # Ensure no world writable files exist
  $facts['world_writable_files'].each | Integer $index, String $file | {
    warning("File ${file} is world writable. Remove this permission or exclude from testing.")
  }

  # Ensure no unowned files or directories exist
  $facts['unowned_files'].each | Integer $index, String $file | {
    warning("File ${file} is unowned. Remove this file or change ownership.")
  }

  # Ensure no ungrouped files or directories exist
  $facts['ungrouped_files'].each | Integer $index, String $file | {
    warning("File ${file} has ungrouped. Remove this file or change group.")
  }

  # Audit SUID executables
  $facts['suid_executables'].each | Integer $index, String $file | {
    warning("File ${file} is an suid executale. Remove this permission or exclude from testing.")
  }

  # Audit GUID executables
  $facts['guid_executables'].each | Integer $index, String $file | {
    warning("File ${file} is a guid executale. Remove this permission or exclude from testing.")
  }
}
