require 'spec_helper'
describe 'harden_centos_os' do
  context 'with default values for all parameters' do
    it { should contain_class('harden_centos_os') }
  end
end
