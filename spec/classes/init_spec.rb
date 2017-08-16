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
            'yum_repos' => ['/etc/yum.repos.d/some.repo'],
            'log_files' => ['/var/log/messages']
          )
        end

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
            'ensure' => 'present'
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

        # Ensure core dumps are restricted
        it {
          should contain_limits__fragment('*/hard/core').with(
            'value' => '0'
          )
        }

        it {
          should contain_sysctl('fs.suid_dumpable').with(
            'ensure' => 'present',
            'value'  => '0'
          )
        }

        # Ensure prelink is disabled
        it {
          should contain_package('prelink').with(
            'ensure' => 'absent'
          )
        }

        # Ensure permissions on /etc/motd are configured
        it {
          should contain_file('/etc/motd').with(
            'ensure' => 'file',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644'
          )
        }

        # Ensure permissions on /etc/issue are configured
        it {
          should contain_file('/etc/issue').with(
            'ensure' => 'file',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644'
          )
        }

        # Ensure permissions on /etc/issue.net are configured
        it {
          should contain_file('/etc/issue.net').with(
            'ensure' => 'file',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644'
          )
        }

        # Ensure chargen services are not enabled
        it {
          should contain_service('chargen-dgram').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        it {
          should contain_service('chargen-stream').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure daytime services are not enabled
        it {
          should contain_service('daytime-dgram').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        it {
          should contain_service('daytime-stream').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure discard services are not enabled
        it {
          should contain_service('discard-dgram').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        it {
          should contain_service('discard-stream').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure echo services are not enabled
        it {
          should contain_service('echo-dgram').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        it {
          should contain_service('echo-stream').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure time services are not enabled
        it {
          should contain_service('time-dgram').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        it {
          should contain_service('time-stream').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure tftp services are not enabled
        it {
          should contain_service('tftp').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure xinetd is not enabled
        it {
          should contain_service('xinetd').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure time synchronization is in use
        # Ensure ntp is configured
        it { should contain_class('ntp') }

        # Ensure Avahi Server is not enabled
        it {
          should contain_service('avahi-daemon').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure cups is not enabled
        it {
          should contain_service('cups').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure DHCP Server is not enabled
        it {
          should contain_service('dhcpd').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure LDAP server is not enabled
        it {
          should contain_service('slapd').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure NFS and RPC are not enabled
        it {
          should contain_service('nfs').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        it {
          should contain_service('rpcbind').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure DNS Server is not enabled
        it {
          should contain_service('named').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure FTP Server is not enabled
        it {
          should contain_service('vsftpd').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure HTTP server is not enabled
        it {
          should contain_service('httpd').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure IMAP and POP3 server is not enabled
        it {
          should contain_service('dovecot').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure Samba is not enabled
        it {
          should contain_service('smb').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure HTTP Proxy Server is not enabled
        it {
          should contain_service('squid').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure SNMP Server is not enabled
        it {
          should contain_service('snmpd').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure mail transfer agent is configured for local-only mode
        it {
          should contain_augeas('inet_interfaces').with(
            'context' => '/files/etc/postfix/main.cf',
            'changes' => [
              'set inet_interfaces localhost'
            ]
          )
        }

        it {
          should contain_service('postfix').with(
            'ensure' => 'running'
          )
        }

        # Ensure NIS Server is not enabled
        it {
          should contain_service('ypserv').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure rsh server is not enabled
        it {
          should contain_service('rsh.socket').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        it {
          should contain_service('rlogin.socket').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        it {
          should contain_service('rexec.socket').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure telnet server is not enabled
        it {
          should contain_service('telnet.socket').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure tftp server is not enabled
        it {
          should contain_service('tftp.socket').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure rsync service is not enabled
        it {
          should contain_service('rsyncd').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure talk server is not enabled
        it {
          should contain_service('ntalk').with(
            'ensure' => 'stopped',
            'enable' => 'false'
          )
        }

        # Ensure NIS Client is not installed
        it {
          should contain_package('ypbind').with(
            'ensure' => 'absent'
          )
        }

        # Ensure rsh client is not installed
        it {
          should contain_package('rsh').with(
            'ensure' => 'absent'
          )
        }

        # Ensure talk client is not installed
        it {
          should contain_package('talk').with(
            'ensure' => 'absent'
          )
        }

        # Ensure telnet client is not installed
        it {
          should contain_package('telnet').with(
            'ensure' => 'absent'
          )
        }

        # Ensure LDAP client is not installed
        it {
          should contain_package('openldap-clients').with(
            'ensure' => 'absent'
          )
        }

        # Ensure IP forwarding is disabled
        it {
          should contain_sysctl('net.ipv4.ip_forward').with(
            'value'  => '0'
          )
        }

        # Ensure packet redirect sending is disabled
        it {
          should contain_sysctl('net.ipv4.conf.all.send_redirects').with(
            'value'  => '0'
          )
        }

        it {
          should contain_sysctl('net.ipv4.conf.default.send_redirects').with(
            'value'  => '0'
          )
        }

        # Ensure source routed packets are not accepted
        it {
          should contain_sysctl('net.ipv4.conf.all.accept_source_route').with(
            'value'  => '0'
          )
        }

        it {
          should contain_sysctl('net.ipv4.conf.default.accept_source_route').with(
            'value'  => '0'
          )
        }

        # Ensure ICMP redirects are not accepted
        it {
          should contain_sysctl('net.ipv4.conf.all.accept_redirects').with(
            'value'  => '0'
          )
        }

        it {
          should contain_sysctl('net.ipv4.conf.default.accept_redirects').with(
            'value'  => '0'
          )
        }

        # Ensure secure ICMP redirects are not accepted
        it {
          should contain_sysctl('net.ipv4.conf.all.secure_redirects').with(
            'value'  => '0'
          )
        }

        it {
          should contain_sysctl('net.ipv4.conf.default.secure_redirects').with(
            'value'  => '0'
          )
        }

        # Ensure suspicious packets are logged
        it {
          should contain_sysctl('net.ipv4.conf.all.log_martians').with(
            'value'  => '1'
          )
        }

        it {
          should contain_sysctl('net.ipv4.conf.default.log_martians').with(
            'value'  => '1'
          )
        }

        # Ensure broadcast ICMP requests are ignored
        it {
          should contain_sysctl('net.ipv4.icmp_echo_ignore_broadcasts').with(
            'value'  => '1'
          )
        }

        # Ensure bogus ICMP responses are ignored
        it {
          should contain_sysctl('net.ipv4.icmp_ignore_bogus_error_responses').with(
            'value'  => '1'
          )
        }

        # Ensure bogus ICMP responses are ignored
        it {
          should contain_sysctl('net.ipv4.conf.all.rp_filter').with(
            'value'  => '1'
          )
        }

        it {
          should contain_sysctl('net.ipv4.conf.default.rp_filter').with(
            'value'  => '1'
          )
        }

        # Ensure TCP SYN Cookies is enabled
        it {
          should contain_sysctl('net.ipv4.tcp_syncookies').with(
            'value'  => '1'
          )
        }

        # Ensure bogus ICMP responses are ignored
        it {
          should contain_sysctl('net.ipv6.conf.all.accept_ra').with(
            'value'  => '0'
          )
        }

        it {
          should contain_sysctl('net.ipv6.conf.default.accept_ra').with(
            'value'  => '0'
          )
        }

        # Ensure bogus ICMP responses are ignored
        it {
          should contain_sysctl('net.ipv6.conf.all.accept_redirects').with(
            'value'  => '0'
          )
        }

        it {
          should contain_sysctl('net.ipv6.conf.default.accept_redirects').with(
            'value'  => '0'
          )
        }

        # Ensure TCP Wrappers is installed
        it {
          should contain_package('tcp_wrappers').with(
            'ensure' => 'present'
          )
        }

        # Ensure /etc/hosts.allow is configured
        # Ensure permissions on /etc/hosts.allow are configured
        it {
          should contain_file('/etc/hosts.allow').with(
            'ensure' => 'file',
            'mode'   => '0644',
            'owner'  => 'root',
            'group'  => 'root'
          )
        }

        # Ensure /etc/hosts.deny is configured
        # Ensure permissions on /etc/hosts.deny are configured
        it {
          should contain_file('/etc/hosts.deny').with(
            'ensure' => 'file',
            'mode'   => '0644',
            'owner'  => 'root',
            'group'  => 'root',
            'content' => 'ALL: ALL'
          )
        }

        # Ensure DCCP is disabled
        it {
          should contain_kmod__install('dccp').with(
            'command' => '/bin/true'
          )
        }

        # Ensure SCTP is disabled
        it {
          should contain_kmod__install('sctp').with(
            'command' => '/bin/true'
          )
        }

        # Ensure RDS is disabled
        it {
          should contain_kmod__install('rds').with(
            'command' => '/bin/true'
          )
        }

        # Ensure TIPC is disabled
        it {
          should contain_kmod__install('tipc').with(
            'command' => '/bin/true'
          )
        }

        # Ensure default deny firewall policy
        it {
          should contain_firewallchain('INPUT:filter:IPv4').with(
            'ensure' => 'present',
            'policy' => 'drop'
          )
        }

        it {
          should contain_firewallchain('OUTPUT:filter:IPv4').with(
            'ensure' => 'present',
            'policy' => 'drop'
          )
        }

        it {
          should contain_firewallchain('FORWARD:filter:IPv4').with(
            'ensure' => 'present',
            'policy' => 'drop'
          )
        }

        # Ensure loopback traffic is configured
        it {
          should contain_firewall('001 accept all input to lo interface').with(
            'chain'   => 'INPUT',
            'proto'   => 'all',
            'iniface' => 'lo',
            'action'  => 'accept'
          )
        }

        it {
          should contain_firewall('002 accept all output to lo interface').with(
            'chain'    => 'OUTPUT',
            'proto'    => 'all',
            'outiface' => 'lo',
            'action'   => 'accept'
          )
        }

        it {
          should contain_firewall('003 drop all to lo 127.0.0.0/8').with(
            'chain'  => 'INPUT',
            'proto'  => 'all',
            'source' => '127.0.0.0/8',
            'action' => 'drop'
          )
        }

        # Ensure outbound and established connections are configured
        it {
          should contain_firewall('004 accept new and established ouput tcp connections').with(
            'chain'  => 'OUTPUT',
            'state'  => %w[NEW ESTABLISHED],
            'action' => 'accept',
            'proto'  => 'tcp'
          )
        }

        it {
          should contain_firewall('005 accept new and established ouput udp connections').with(
            'chain'  => 'OUTPUT',
            'state'  => %w[NEW ESTABLISHED],
            'action' => 'accept',
            'proto'  => 'udp'
          )
        }

        it {
          should contain_firewall('006 accept new and established ouput icmp connections').with(
            'chain'  => 'OUTPUT',
            'state'  => %w[NEW ESTABLISHED],
            'action' => 'accept',
            'proto'  => 'icmp'
          )
        }

        it {
          should contain_firewall('007 accept estalished input tcp connections').with(
            'chain'  => 'INPUT',
            'state'  => 'ESTABLISHED',
            'action' => 'accept',
            'proto'  => 'tcp'
          )
        }

        it {
          should contain_firewall('008 accept estalished input udp connections').with(
            'chain'  => 'INPUT',
            'state'  => 'ESTABLISHED',
            'action' => 'accept',
            'proto'  => 'udp'
          )
        }

        it {
          should contain_firewall('009 accept estalished input icmp connections').with(
            'chain'  => 'INPUT',
            'state'  => 'ESTABLISHED',
            'action' => 'accept',
            'proto'  => 'icmp'
          )
        }

        it {
          should contain_firewall('010 open ssh port').with(
            'chain'  => 'INPUT',
            'dport'  => 22,
            'state'  => 'NEW',
            'action' => 'accept',
            'proto'  => 'tcp'
          )
        }

        # Ensure rsyslog Service is enabled
        it { should contain_class('rsyslog::client') }

        it { should contain_class('harden_centos_os') }
      end
    end
  end
end
