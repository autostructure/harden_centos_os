#
class harden_centos_os::configure {

  # 3.4.2 Ensure /etc/hosts.allow is configured
  # 3.4.4 Ensure permissions on /etc/hosts.allow are configured
  if($harden_centos_os::ensure__etc_hosts_allow_is_configured) {
    file { '/etc/hosts.allow':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => "ALL: ${facts['network']}/${facts['netmask']}",
    }
  }

  # 3.4.3 Ensure /etc/hosts.deny is configured
  # 3.4.5 Ensure permissions on /etc/hosts.deny are 644
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

  # 5.1.3 Ensure permissions on /etc/cron.hourly are configured
  if($harden_centos_os::ensure_permissions_on__etc_cron_hourly_are_configured) {
    file { '/etc/cron_hourly':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  # 5.1.4 Ensure permissions on /etc/cron.daily are configured
  if($harden_centos_os::ensure_permissions_on__etc_cron_daily_are_configured) {
    file { '/etc/cron_daily':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  # 5.1.5 Ensure permissions on /etc/cron.weekly are configured
  if($harden_centos_os::ensure_permissions_on__etc_cron_weekly_are_configured) {
    file { '/etc/cron_weekly':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  # 5.1.6 Ensure permissions on /etc/cron.monthly are configured
  if($harden_centos_os::ensure_permissions_on__etc_cron_monthly_are_configured) {
    file { '/etc/cron_monthly':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  # 5.1.7 Ensure permissions on /etc/cron.d are configured
  if($harden_centos_os::ensure_permissions_on__etc_cron_d_are_configured) {
    file { '/etc/cron_d':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  # 5.1.8 Ensure at/cron is restricted to authorized users
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

  # 6.1.2 Ensure permissions on /etc/passwd are configured
  if($harden_centos_os::ensure_permissions_on__etc_passwd_are_configured) {
    file { '/etc/passwd':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }

  # 6.1.3 Ensure permissions on /etc/shadow are configured
  if($harden_centos_os::ensure_permissions_on__etc_shadow_are_configured) {
    file { '/etc/shadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
  }

  # 6.1.4 Ensure permissions on /etc/group are configured
  if($harden_centos_os::ensure_permissions_on__etc_group_are_configured) {
    file { '/etc/group':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }

  # 6.1.5 Ensure permissions on /etc/gshadow are configured
  if($harden_centos_os::ensure_permissions_on__etc_gshadow_are_configured) {
    file { '/etc/gshadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
  }

  # 6.1.6 Ensure permissions on /etc/passwd- are configured
  if($harden_centos_os::ensure_permissions_on__etc_passwd__are_configured) {
    file { '/etc/passwd-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }

  # 6.1.7 Ensure permissions on /etc/shadow- are configured
  if($harden_centos_os::ensure_permissions_on__etc_shadow__are_configured) {
    file { '/etc/shadow-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }

  # 6.1.8 Ensure permissions on /etc/group-
  if($harden_centos_os::ensure_permissions_on__etc_group__are_configured) {
    file { '/etc/group-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }

  # 6.1.9 Ensure permissions on /etc/gshadow- are configured
  if($harden_centos_os::ensure_permissions_on__etc_gshadow__are_configured) {
    file { '/etc/gshadow-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
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

  # 5.4.4 Ensure default user umask is 027 or more restrictive
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

  # Notes:
  # This recommendation is designed around the grub bootloader, if LILO or
  # another bootloader is in use in your environment enact equivalent settings.
  # 1.4.1 Ensure permissions on bootloader config are configured
  if($harden_centos_os::ensure_permissions_on_bootloader_config_are_configured) {
    file { '/boot/grub2/grub.cfg':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
  }

  # Notes:
  # This recommendation is designed around the grub bootloader, if LILO or
  # another bootloader is in use in your environment enact equivalent settings.
  # 1.4.2 Ensure bootloader password is set

  # grub-mkpasswd-pbkdf2
  # /usr/bin/grub2-mkpasswd-pbkdf2

# Create an encrypted password with grub-mkpasswd-pbkdf2 :
# grub2-mkpasswd-pbkdf2
# Enter password: <password>
# Reenter password: <password>
# Your PBKDF2 is <encrypted-password>
#
# Add the following into /etc/grub.d/01_users
# or a custom /etc/grub.d configuration file:
# cat <<EOF
# set superusers="<username>"
# password_pbkdf2 <username> <encrypted-password>
# EOF
#
# Run the following command to update the grub2 configuration:
# grub2-mkconfig > /boot/grub2/grub.cfg


#
# [root@puppet ~]# cat /etc/grub.d/01_users
#
# #!/bin/sh -e
# cat << EOF
# if [ -f \${prefix}/user.cfg ]; then
#   source \${prefix}/user.cfg
#   if [ -n "\${GRUB2_PASSWORD}" ]; then
#     set superusers="root"
#     export superusers
#     password_pbkdf2 root \${GRUB2_PASSWORD}
#   fi
# fi
# EOF
# [root@puppet ~]#
#
# [root@puppet ~]# grub2-mkpasswd-pbkdf2
# Enter password:
# Reenter password:
# PBKDF2 hash of your password is
# grub.pbkdf2.sha512.10000.329B6CEC2DF4B41A44B310BEB413E974101840D868CE15F63EE40F2E31D0E8C8151C9C0C69E743727469777906D18407DED2A23C4095CFF1D6544AF00D2433B3.6B0E95761F40B66960B12336457AC25E563BF6D0EAA0EE3DD0122634A674B1849E6FC2C0246360E289ECB0A27CA5E5CADE943BDBD2B101C47139F0D0796CE144
# [root@puppet ~]#

  # 1.4.3 Ensure authentication required for single user mode
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

  # 1.2.3 Ensure gpgcheck is globally activated
  if($harden_centos_os::ensure_gpgcheck_is_globally_activated) {
    augeas { 'yum_gpgcheck':
      context => '/files/etc/yum.conf/main',
      changes => ['set gpgcheck 1'],
    }
  }

  # 2.2.15 Ensure mail transfer agent is configured for local-only mode
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

  # 1.2.3 Ensure gpgcheck is globally activated
  # Set gpgcheck on yum repositories
  $facts['yum_repos'].each | Integer $index, String $file | {
    augeas { "${index}_gpgcheck":
      context => "/files${file}",
      changes => [
        'setm /*[label() =~ regexp(\'^[^#]+\')] gpgcheck 1',
      ],
    }
  }

  # 4.2.4 Ensure permissions on all logfiles are configured
  # Ensure permissions on all logfiles are configured
  $facts['log_files'].each | Integer $index, String $file | {
    file { $file:
      ensure => file,
      mode   => 'g-wx,o-rwx',
    }
  }

  # 6.1.10 Ensure no world writable files exist
  # Ensure no world writable files exist
  $facts['world_writable_files'].each | Integer $index, String $file | {
    warning("File ${file} is world writable. Remove this permission or exclude from testing.")
  }

  # 6.1.11 Ensure no unowned files or directories exist
  # Ensure no unowned files or directories exist
  $facts['unowned_files'].each | Integer $index, String $file | {
    warning("File ${file} is unowned. Remove this file or change ownership.")
  }

  # 6.1.12 Ensure no ungrouped files or directories exist
  # Ensure no ungrouped files or directories exist
  $facts['ungrouped_files'].each | Integer $index, String $file | {
    warning("File ${file} has ungrouped. Remove this file or change group.")
  }

  # 6.1.13 Audit SUID executables
  # Audit SUID executables
  $facts['suid_executables'].each | Integer $index, String $file | {
    warning("File ${file} is an suid executale. Remove this permission or exclude from testing.")
  }

  # 6.1.14 Audit SGID executables
  # Audit GUID executables
  $facts['guid_executables'].each | Integer $index, String $file | {
    warning("File ${file} is a guid executale. Remove this permission or exclude from testing.")
  }
}
