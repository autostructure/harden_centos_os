require 'spec_helper'

describe 'harden_centos_os' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts.merge(
            'ssh_version' => 'OpenSSHxxx',
            'ssh_version_numeric' => '1.0.0'
          )
        end

        # let(:params) {
        #   {
        #     managed_files: {
        #       '/etc/motd' => {
        #         'ensure' => 'directory',
        #         'owner' => 'root',
        #         'group' => 'root',
        #         'mode' => '0644',
        #       },
        #       '/etc/issue' => {
        #         'ensure' => 'directory',
        #         'owner' => 'root',
        #         'group' => 'root',
        #         'mode' => '0644',
        #       },
        #       '/etc/issue.net' => {
        #         'ensure' => 'file',
        #         'owner' => 'root',
        #         'group' => 'root',
        #         'mode' => '0644',
        #       },
        #     },
        #   }
        # }

        it { is_expected.to compile.with_all_deps }

        it { should contain_class('harden_centos_os') }
      end
    end
  end
end
