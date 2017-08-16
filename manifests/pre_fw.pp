#
class harden_centos_os::pre_fw {
  firewall { '001 accept all input to lo interface':
    chain   => 'INPUT',
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept',
  }
  -> firewall { '002 accept all output to lo interface':
    chain    => 'OUTPUT',
    proto    => 'all',
    outiface => 'lo',
    action   => 'accept',
  }
  -> firewall { '003 drop all to lo 127.0.0.0/8':
    chain  => 'INPUT',
    proto  => 'all',
    source => '127.0.0.0/8',
    action => 'drop',
  }
  -> firewall { '004 accept new and established ouput tcp connections':
    chain  => 'OUTPUT',
    state  => ['NEW', 'ESTABLISHED'],
    action => 'accept',
    proto  => 'tcp',
  }
  -> firewall { '005 accept new and established ouput udp connections':
    chain  => 'OUTPUT',
    state  => ['NEW', 'ESTABLISHED'],
    action => 'accept',
    proto  => 'udp',
  }
  -> firewall { '006 accept new and established ouput icmp connections':
    chain  => 'OUTPUT',
    state  => ['NEW', 'ESTABLISHED'],
    action => 'accept',
    proto  => 'icmp',
  }
  -> firewall { '007 accept estalished input tcp connections':
    chain  => 'INPUT',
    state  => 'ESTABLISHED',
    action => 'accept',
    proto  => 'tcp',
  }
  -> firewall { '008 accept estalished input udp connections':
    chain  => 'INPUT',
    state  => 'ESTABLISHED',
    action => 'accept',
    proto  => 'udp',
  }
  -> firewall { '009 accept estalished input icmp connections':
    chain  => 'INPUT',
    state  => 'ESTABLISHED',
    action => 'accept',
    proto  => 'icmp',
  }
  -> firewall { '010 open ssh port':
    chain  => 'INPUT',
    dport  => 22,
    state  => 'NEW',
    action => 'accept',
    proto  => 'tcp',
  }
}
