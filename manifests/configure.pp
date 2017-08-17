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
