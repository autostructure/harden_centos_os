require 'beaker-rspec/spec_helper'
require 'beaker-rspec/helpers/serverspec'
require 'beaker/puppet_install_helper'

run_puppet_install_helper unless ENV['BEAKER_provision'] == 'no'

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    hosts.each do |host|
      # Install module and dependencies
      copy_module_to(host, source: proj_root, module_name: 'harden_centos_os')

      on host, puppet('module install --ignore-dependencies --version 2.2.0 camptocamp-kmod'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 1.7.0 ghoneycutt-common'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 3.54.0 ghoneycutt-ssh'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 2.1.3 herculesteam-augeasproviders_core'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 2.2.0 herculesteam-augeasproviders_sysctl'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 1.0.3 lhinds-aide'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 1.9.0 puppetlabs-firewall'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 0.1.0 puppetlabs-limits'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 6.2.0 puppetlabs-ntp'), acceptable_exit_codes: [0]
      on host, puppet('module install --force --version 4.18.0 puppetlabs-stdlib'), acceptable_exit_codes: [0]
      on host, puppet('module install --ignore-dependencies --version 5.0.0 saz-rsyslog'), acceptable_exit_codes: [0]
    end
  end
end
