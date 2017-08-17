# Class: harden_centos_os
# ===========================
#
# Full description of class harden_centos_os here.
#
# Parameters
# ----------
#
# Document parameters here.
#
# * `sample parameter`
# Explanation of what this parameter affects and what it defaults to.
# e.g. "Specify one or more upstream ntp servers as an array."
#
# Variables
# ----------
#
# Here you should define a list of variables that this module would require.
#
# * `sample variable`
#  Explanation of how this variable affects the function of this class and if
#  it has a default. e.g. "The parameter enc_ntp_servers must be set by the
#  External Node Classifier as a comma separated list of hostnames." (Note,
#  global variables should be avoided in favor of class parameters as
#  of Puppet 2.6.)
#
# Examples
# --------
#
# @example
#    class { 'harden_centos_os':
#      servers => [ 'pool.ntp.org', 'ntp.local.company.com' ],
#    }
#
# Authors
# -------
#
# Author Name <jeff@autostructure.com>
#
# Copyright
# ---------
#
# Copyright 2017 Autostructure.
#
class harden_centos_os(
  String $motd,
  String $issue,
  Array $ntp_servers,
  Hash $managed_files,
  Hash $kernel_module_options,
  Hash $kernel_module_installs,
  Hash $managed_packages,
  Hash $sshd_configs,
  Hash $kernel_parameters,
  Hash $managed_services,
  Hash $file_line_rules,
  Hash $augeas_rules,
  Hash $limits,
) {
  Firewall {
    require => undef,
  }

  resources { 'firewall':
    purge => true,
  }

  # Ensure time synchronization is in use
  class { '::ntp':
    servers => [ 'ntp1.corp.com', 'ntp2.corp.com' ],
  }

  class { '::harden_centos_os::install': }
  -> class { '::harden_centos_os::configure': }
  ~> class { '::harden_centos_os::run': }
  -> Class['::harden_centos_os']

  # class { '::harden_centos_os::kernel_parameters': }
  # ~> class { '::harden_centos_os::kernel_parameters_flush': }
  # -> Class['::harden_centos_os']

  class { '::harden_centos_os::pre_fw': }
  -> class { '::harden_centos_os::post_fw': }
  -> Class['::harden_centos_os']
}
