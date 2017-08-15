require 'spec_helper'

describe 'harden_centos_os' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts.merge(
            'ssh_version' => 'OpenSSHxxx',
            'ssh_version_numeric' => '1.0.0',
            'augeasversion' => '1.0.0',
            'yum_repos' => ['/etc/yum.repos.d/some.repo']
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

        # Disable unused filesystems

        # Ensure mounting of cramfs filesystems is disabled
        it {
          should contain_kmod__install('cramfs').with(
            'command' => '/bin/true'
          )
        }

        # Ensure mounting of freevxfs filesystems is disabled
        it {
          should contain_kmod__install('freevxfs').with(
            'command' => '/bin/true'
          )
        }

        # Ensure mounting of jffs2 filesystems is disabled
        it {
          should contain_kmod__install('jffs2').with(
            'command' => '/bin/true'
          )
        }

        # Ensure mounting of hfs filesystems is disabled
        it {
          should contain_kmod__install('hfs').with(
            'command' => '/bin/true'
          )
        }

        # Ensure mounting of hfsplus filesystems is disabled
        it {
          should contain_kmod__install('hfsplus').with(
            'command' => '/bin/true'
          )
        }

        # Ensure mounting of squashfs filesystems is disabled
        it {
          should contain_kmod__install('squashfs').with(
            'command' => '/bin/true'
          )
        }

        # Ensure mounting of udf filesystems is disabled
        it {
          should contain_kmod__install('udf').with(
            'command' => '/bin/true'
          )
        }

        # Ensure mounting of FAT filesystems is disabled
        it {
          should contain_kmod__install('vfat').with(
            'command' => '/bin/true'
          )
        }

        # Disable Automounting
        it {
          should contain_service('autofs').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure gpgcheck is globally activated
        it {
          should contain_augeas('yum_gpgcheck').with(
            'context' => '/files/etc/yum.conf/main',
            'changes' => [
              'set gpgcheck 1'
            ]
          )
        }

        # Ensure AIDE is installed
        it {
          should contain_package('aide').with(
            'ensure' => 'installed'
          )
        }

        # Ensure filesystem integrity is regularly checked
        # TODO

        # Ensure permissions on bootloader config are configured
        it {
          should contain_file('/boot/grub2/grub.cfg').with(
            'ensure' => 'file',
            'mode'   => 'og-rwx',
            'owner'  => 'root',
            'group'  => 'root'
          )
        }

        # Ensure authentication required for single user mode
        it {
          should contain_file_line('rescue_service_sulogin').with(
            'ensure' => 'present',
            'path'   => '/usr/lib/systemd/system/rescue.service',
            'line'   => 'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
            'match'  => '^ExecStart=',
            'replace' => 'true'
          )
        }

        it {
          should contain_file_line('emergency_service_sulogin').with(
            'ensure' => 'present',
            'path'   => '/usr/lib/systemd/system/emergency.service',
            'line'   => 'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
            'match'  => '^ExecStart=',
            'replace' => 'true'
          )
        }

        # Ensure package manager repositories are configured
        # it {
        #   should contain_kmod__install('vfat').with(
        #     'command' => '/bin/true'
        #   )
        # }
#
        # # Ensure mounting of FAT filesystems is disabled
        # it {
        #   should contain_kmod__install('vfat').with(
        #     'command' => '/bin/true'
        #   )
        # }
#
        # # Ensure mounting of FAT filesystems is disabled
        # it {
        #   should contain_kmod__install('vfat').with(
        #     'command' => '/bin/true'
        #   )
        # }
#
        # # Ensure mounting of FAT filesystems is disabled
        # it {
        #   should contain_kmod__install('vfat').with(
        #     'command' => '/bin/true'
        #   )
        # }
#
        # # Ensure mounting of FAT filesystems is disabled
        # it {
        #   should contain_kmod__install('vfat').with(
        #     'command' => '/bin/true'
        #   )
        # }
#
        # # Ensure mounting of FAT filesystems is disabled
        # it {
        #   should contain_kmod__install('vfat').with(
        #     'command' => '/bin/true'
        #   )
        # }
#
        # # Ensure mounting of FAT filesystems is disabled
        # it {
        #   should contain_kmod__install('vfat').with(
        #     'command' => '/bin/true'
        #   )
        # }
#
        # # Ensure mounting of FAT filesystems is disabled
        # it {
        #   should contain_kmod__install('vfat').with(
        #     'command' => '/bin/true'
        #   )
        # }

        it { should contain_class('harden_centos_os') }
      end
    end
  end
end
