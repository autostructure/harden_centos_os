#
class harden_centos_os::configure {
  # Enforce file and directory rules
  $::harden_centos_os::managed_files.each | String $key, Hash $value | {
    file { $key:
      ensure  => $value['ensure'],
      owner   => $value['owner'],
      group   => $value['group'],
      mode    => $value['mode'],
      content => $value['content'],
    }
  }

  # Install necessary file_line rules
  $::harden_centos_os::file_line_rules.each | String $key, Hash $values | {
    file_line { $key:
      ensure  => $values['ensure'],
      match   => $values['match'],
      replace => $values['replace'],
      path    => $values['path'],
      line    => $values['line'],
    }
  }

  # Enforce augeas file rules
  $::harden_centos_os::augeas_rules.each | String $key, Hash $values | {
    augeas { $key:
      context => $values['context'],
      changes => $values['changes'],
    }
  }

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
}
