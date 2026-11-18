package ProFTPD::Tests::Modules::mod_proxy::ssh::certs;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Carp;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IO::Socket::INET;
use Time::HiRes qw(gettimeofday tv_interval usleep);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  # RSA Host CA key tests
  proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_rsa_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_ecdsa256_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_ecdsa384_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_ecdsa521_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ed25519_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  # ECDSA256 Host CA key tests
  proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_rsa_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ecdsa256_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ecdsa384_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ecdsa521_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ed25519_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  # ECDSA384 Host CA key tests
  proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_rsa_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_ecdsa256_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_ecdsa384_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_ecdsa521_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_ed25519_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  # ECDSA521 Host CA key tests
  proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_rsa_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_ecdsa256_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_ecdsa384_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_ecdsa521_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_ed25519_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  # ED25519 Host CA key tests
  proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_rsa_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_ecdsa256_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_ecdsa384_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_ecdsa521_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_ed25519_certificate => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  # Miscellaneous
  proxy_reverse_backend_ssh_hostbased_auth_certopts_allow_empty_principals => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_certopts_allow_match_principals => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_revoked_rsa_key => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_revoked_rsa_ca_key => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostbased_auth_revoked_ed25519_key => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_sftp reverse)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  my $required = [qw(
    Net::SSH2
  )];

  foreach my $req (@$required) {
    eval "use $req";
    if ($@) {
      print STDERR "\nWARNING:\n + Module '$req' not found, skipping all tests\n";

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Unable to load $req: $@\n";
      }

      return qw(testsuite_empty_test);
    }
  }

  return testsuite_get_runnable_tests($TESTS);
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  unless (chmod(0400, $rsa_host_key)) {
    die("Can't set perms on mod_sftp hostkeys: $!");
  }

  # And ensure that the necessary test certificate are live enough for us.
  my $cmd = "$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/mkcerts.pl";

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Executing command: $cmd\n";
  }
  `$cmd`;
}

sub get_reverse_proxy_config {
  my $tmpdir = shift;
  my $log_file = shift;
  my $vhost_port = shift;

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/proxy");

  my $config = {
    ProxyEngine => 'on',
    ProxyLog => $log_file,
    ProxyReverseServers => "sftp://127.0.0.1:$vhost_port",
    ProxyRole => 'reverse',
    ProxyTables => $table_dir,
  };

  return $config;
}

sub proxy_reverse_backend_ssh_hostbased_auth {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $rfc4716_ca_keys = shift;
  my $cert = shift;
  my $cert_privkey = shift;
  my $addl_directives = shift;
  my $failure_expected = shift;
  $failure_expected = 0 unless defined($failure_expected);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $user_privkey = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $user_pubkey = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");

  unless (chmod(0400, $cert_privkey)) {
    die("Can't set perms on $cert_privkey: $!");
  }

  my $authorized_ca_keys = File::Spec->rel2abs("$tmpdir/authorized_ca_keys");
  unless (copy($rfc4716_ca_keys, $authorized_ca_keys)) {
    die("Can't copy $rfc4716_ca_keys to $authorized_ca_keys: $!");
  }

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxySFTPVerifyServer} = 'off';
  $proxy_config->{ProxySFTPHostCertificate} = $cert;
  $proxy_config->{ProxySFTPHostKey} = $cert_privkey;

  my $sftp_config = [
    'SFTPEngine on',
    "SFTPLog $setup->{log_file}",
    "SFTPHostKey $rsa_host_key",
    "SFTPCiphers $cipher_algo",
    "SFTPDigests $digest_algo",
    "SFTPKeyExchanges $kex_algo",
    "SFTPAuthorizedHostCAKeys file:$authorized_ca_keys",
  ];
  if (defined($addl_directives)) {
    push(@$sftp_config, @$addl_directives);
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.certs:20 proxy.ssh.keys:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:30 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $setup->{auth_user_file}
  AuthGroupFile $setup->{auth_group_file}
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_sftp.c>
EOC

    foreach my $item (@$sftp_config) {
      print $fh "    $item\n";
    }

    print $fh <<EOC;
  </IfModule>
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(1);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $user_pubkey,
          $user_privkey)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Restore permissions
  unless (chmod(0644, $cert_privkey)) {
    die("Can't set perms on $cert_privkey: $!");
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /Accepted .*? host certificate ID/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected SFTPLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@ unless $ex;
  }

  if ($failure_expected == 1) {
    # If we have an exception/failure already, clear it, as it is expected.
    if ($ex) {
      $ex = undef;

    # Otherwise, the lack of an exception/failure, when we expect one, is
    # itself a problem.
    } else {
      $ex = 'Test succeeded unexpectedly' unless $ex;
    }
  }

  test_cleanup($setup, $ex);
}

sub proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_rsa_certificate {
  my $self = shift;

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_ecdsa256_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa256_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_ecdsa256_cert.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_ecdsa384_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa384_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_ecdsa384_cert.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_ecdsa521_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa521_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_ecdsa521_cert.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_rsa_ca_ed25519_certificate {
  my $self = shift;

  my $eddsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_openssh_ed25519_key");
  my $eddsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_ed25519_cert.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_rsa_certificate {
  my $self = shift;

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_rsa_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ecdsa256_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa256_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_ecdsa256_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ecdsa384_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa384_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_ecdsa384_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ecdsa521_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa521_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_ecdsa521_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa256_ca_ed25519_certificate {
  my $self = shift;

  my $eddsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_openssh_ed25519_key");
  my $eddsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa256_ca_ed25519_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa256_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_rsa_certificate {
  my $self = shift;

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_rsa_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_ecdsa256_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa256_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_ecdsa256_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_ecdsa384_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa384_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_ecdsa384_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_ecdsa521_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa521_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_ecdsa521_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa384_ca_ed25519_certificate {
  my $self = shift;

  my $eddsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_openssh_ed25519_key");
  my $eddsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa384_ca_ed25519_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa384_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_rsa_certificate {
  my $self = shift;

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_rsa_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_ecdsa256_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa256_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_ecdsa256_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_ecdsa384_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa384_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_ecdsa384_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_ecdsa521_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa521_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_ecdsa521_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ecdsa521_ca_ed25519_certificate {
  my $self = shift;

  my $eddsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_openssh_ed25519_key");
  my $eddsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ecdsa521_ca_ed25519_cert.pub");
  my $ecdsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ecdsa521_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $ecdsa_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_rsa_certificate {
  my $self = shift;

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ed25519_ca_rsa_cert.pub");
  my $eddsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $eddsa_ca_keys, $rsa_cert,
    $rsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_ecdsa256_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa256_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ed25519_ca_ecdsa256_cert.pub");
  my $eddsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $eddsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_ecdsa384_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa384_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ed25519_ca_ecdsa384_cert.pub");
  my $eddsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $eddsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_ecdsa521_certificate {
  my $self = shift;

  my $ecdsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_ecdsa521_key");
  my $ecdsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ed25519_ca_ecdsa521_cert.pub");
  my $eddsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $eddsa_ca_keys, $ecdsa_cert,
    $ecdsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_ed25519_ca_ed25519_certificate {
  my $self = shift;

  my $eddsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_openssh_ed25519_key");
  my $eddsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_ed25519_ca_ed25519_cert.pub");
  my $eddsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_ed25519_ca_keys");

  proxy_reverse_backend_ssh_hostbased_auth($self, $eddsa_ca_keys, $eddsa_cert,
    $eddsa_priv_key);
}

sub proxy_reverse_backend_ssh_hostbased_auth_certopts_allow_empty_principals {
  my $self = shift;

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert_empty_principals.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  my $addl_configs = [
    'SFTPCertificateOptions AllowEmptyPrincipals',
  ];

  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $rsa_cert,
    $rsa_priv_key, $addl_configs);
}

sub proxy_reverse_backend_ssh_hostbased_auth_certopts_allow_match_principals {
  my $self = shift;

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert_match_principals.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  my $addl_configs = [
    'SFTPCertificateOptions AllowMatchPrincipals',
  ];

  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $rsa_cert,
    $rsa_priv_key, $addl_configs);
}

sub proxy_reverse_backend_ssh_hostbased_auth_revoked_rsa_key {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  my $revoked_keys = File::Spec->rel2abs("$tmpdir/revoked_keys");
  unless (copy($rsa_pub_key, $revoked_keys)) {
    die("Can't copy $rsa_pub_key to $revoked_keys: $!");
  }

  my $addl_configs = [
    "SFTPRevokedKeys file:$revoked_keys",
  ];

  # With this configuration, we expect the login to fail, due to the use
  # of a revoked key.
  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $rsa_cert,
    $rsa_priv_key, $addl_configs, 1);
}

sub proxy_reverse_backend_ssh_hostbased_auth_revoked_rsa_ca_key {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_rsa_cert.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  my $revoked_keys = File::Spec->rel2abs("$tmpdir/revoked_keys");
  unless (copy($rsa_ca_keys, $revoked_keys)) {
    die("Can't copy $rsa_ca_keys to $revoked_keys: $!");
  }

  my $addl_configs = [
    "SFTPRevokedKeys file:$revoked_keys",
  ];

  # With this configuration, we expect the login to fail, due to the use
  # of a revoked key.
  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $rsa_cert,
    $rsa_priv_key, $addl_configs, 1);
}

sub proxy_reverse_backend_ssh_hostbased_auth_revoked_ed25519_key {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $eddsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_openssh_ed25519_key");
  my $eddsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_openssh_ed25519_keys");
  my $eddsa_cert = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/host_rsa_ca_ed25519_cert.pub");
  my $rsa_ca_keys = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/certs/authorized_host_rsa_ca_keys");

  my $revoked_keys = File::Spec->rel2abs("$tmpdir/revoked_keys");
  unless (copy($eddsa_pub_key, $revoked_keys)) {
    die("Can't copy $eddsa_pub_key to $revoked_keys: $!");
  }

  my $addl_configs = [
    "SFTPRevokedKeys file:$revoked_keys",
  ];

  # With this configuration, we expect the login to fail, due to the use
  # of a revoked key.
  proxy_reverse_backend_ssh_hostbased_auth($self, $rsa_ca_keys, $eddsa_cert,
    $eddsa_priv_key, $addl_configs, 1);
}

1;
