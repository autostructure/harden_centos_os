require 'puppetlabs_spec_helper/module_spec_helper'
require 'rspec-puppet-facts'
require 'hiera'

include RspecPuppetFacts

if ENV['COVERAGE'] == 'yes'
  require 'coveralls'
  Coveralls.wear!
end

require 'rspec-puppet'

RSpec.configure do |c|
  c.module_path     = File.join(File.dirname(File.expand_path(__FILE__)), 'fixtures', 'modules')
  c.manifest_dir    = File.join(File.dirname(File.expand_path(__FILE__)), 'fixtures', 'manifests')
  c.manifest        = File.join(File.dirname(File.expand_path(__FILE__)), 'fixtures', 'manifests', 'site.pp')
  c.hiera_config    = 'hiera.yaml'
  c.environmentpath = File.join(Dir.pwd, 'spec')

  # c.hiera_config = 'spec/fixtures/hiera/hiera.yaml'

  c.after(:suite) do
    RSpec::Puppet::Coverage.report!
  end
end
