#
class harden_centos_os::pre_fw {
  firewall { '001 accept all to lo interface':
    chain   => 'INPUT',
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept',
  }
  -> firewall { '002 accept all to lo interface':
    chain    => 'OUTPUT',
    proto    => 'all',
    outiface => 'lo',
    action   => 'accept',
  }
  -> firewall { '003 accept all to lo interface':
    chain  => 'INPUT',
    proto  => 'all',
    source => '127.0.0.0/8',
    action => 'drop',
  }
  -> firewall { '004 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
    chain  => 'OUTPUT',
    state  => ['NEW', 'ESTABLISHED'],
    action => 'accept',
    proto  => 'tcp',
  }
  -> firewall { '005 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
    chain  => 'OUTPUT',
    state  => ['NEW', 'ESTABLISHED'],
    action => 'accept',
    proto  => 'udp',
  }
  -> firewall { '006 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
    chain  => 'OUTPUT',
    state  => ['NEW', 'ESTABLISHED'],
    action => 'accept',
    proto  => 'icmp',
  }
  -> firewall { '007 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
    chain  => 'INPUT',
    state  => 'ESTABLISHED',
    action => 'accept',
    proto  => 'tcp',
  }
  -> firewall { '008 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
    chain  => 'INPUT',
    state  => 'ESTABLISHED',
    action => 'accept',
    proto  => 'udp',
  }
  -> firewall { '009 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
    chain  => 'INPUT',
    state  => 'ESTABLISHED',
    action => 'accept',
    proto  => 'icmp',
  }
  -> firewall { '010 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
    chain  => 'INPUT',
    dport  => 22,
    state  => 'NEW',
    action => 'accept',
    proto  => 'tcp',
  }
}
