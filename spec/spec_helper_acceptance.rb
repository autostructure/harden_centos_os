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

      on host, puppet('module install camptocamp-kmod'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install ghoneycutt-common'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install ghoneycutt-ssh'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install herculesteam-augeasproviders_core'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install herculesteam-augeasproviders_sysctl'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install lhinds-aide'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install puppetlabs-concat'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install puppetlabs-firewall'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install puppetlabs-stdlib'), { :acceptable_exit_codes => [0] }
      on host, puppet('module install saz-rsyslog'), { :acceptable_exit_codes => [0] }
    end
  end
end
