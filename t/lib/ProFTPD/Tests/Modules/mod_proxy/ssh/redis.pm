package ProFTPD::Tests::Modules::mod_proxy::ssh::redis;

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
  proxy_reverse_backend_ssh_verify_server_off_with_redis => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_redis mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_verify_server_on_with_redis => {
    order => ++$order,
    test_class => [qw(forking mod_proxy mod_redis mod_sftp reverse)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  my $required = [qw(
    MIME::Base64
    Net::SSH2
    Redis
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

# TODO: Note that this test is used for manually reviewing the generated logs;
# it does NOT currently fail if hostkey caching fails (although it should).
sub proxy_reverse_backend_ssh_verify_server_off_with_redis {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyDatastore} = 'Redis mod_proxy.testsuite.ssh.';
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxySFTPVerifyServer} = 'off';

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $redis_server = '127.0.0.1';
  if (defined($ENV{REDIS_HOST})) {
    $redis_server = $ENV{REDIS_HOST};
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.db:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.redis:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 redis:30 ssh2:20 sftp:20 table:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_redis.c' => {
        RedisEngine => 'on',
        RedisServer => "$redis_server:6379",
        RedisTimeouts => '2000 500',
        RedisLog => $setup->{log_file},
      },

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
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo
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

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();

      # We now connect again, to check the just-stored hostkey.
      $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
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

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $no_existing = 0;
      my $hostkey_matches = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /no existing hostkey stored for vhost ID/) {
          $no_existing = 1;
        }

        if ($line =~ /stored hostkey matches current hostkey for vhost/) {
          $hostkey_matches = 1;
          last;
        }
      }

      close($fh);

      $self->assert($no_existing, test_msg("Did not see expected TraceLog messages about no existing stored hostkey"));
      $self->assert($hostkey_matches, test_msg("Did not see expected TraceLog messages about stored hostkey matching"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub redis_set_hostkey {
  my $redis_server = shift;
  my $key = shift;
  my $algo = shift;
  my $blob = shift;

  use MIME::Base64;
  use Redis;

  my $redis = Redis->new(
    server => "$redis_server:6379",
    reconnect => 5,
  );

  $redis->del($key);
  $redis->hset($key, 'algo', $algo);
  $redis->hset($key, 'blob', encode_base64($blob));
  $redis->quit();

  return 1;
}

sub proxy_reverse_backend_ssh_verify_server_on_with_redis {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';

  my $redis_namespace = 'mod_proxy.testsuite.ssh.';
  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyDatastore} = "Redis $redis_namespace";
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxySFTPVerifyServer} = 'on';

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $redis_server = '127.0.0.1';
  if (defined($ENV{REDIS_HOST})) {
    $redis_server = $ENV{REDIS_HOST};
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.db:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.redis:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 redis:30 ssh2:20 sftp:20 table:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_redis.c' => {
        RedisEngine => 'on',
        RedisServer => "$redis_server:6379",
        RedisTimeouts => '2000 500',
        RedisLog => $setup->{log_file},
      },

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
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo
  </IfModule>
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # We force a hostkey mismatch by manually creating the expected Redis entry,
  # populated with a hostkey entry that will not match.
  #
  # Note that we have to do it here, once we know the dynamically allocated
  # port number.
  my $redis_key = $redis_namespace . 'proxy_ssh_hostkeys:' . $proxy_config->{ProxyReverseServers};
  redis_set_hostkey($redis_server, $redis_key, 'ssh-ed25519', 'foobar');

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

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
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

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $have_existing = 0;
      my $hostkey_mismatch = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /found stored .*? for vhost ID/) {
          $have_existing = 1;
        }

        if ($line =~ /stored hostkey does not match current hostkey .*? ProxySFTPVerifyServer is enabled/) {
          $hostkey_mismatch = 1;
          last;
        }
      }

      close($fh);

      $self->assert($have_existing, test_msg("Did not see expected TraceLog messages about existing stored hostkey"));
      $self->assert($hostkey_mismatch, test_msg("Did not see expected TraceLog messages about stored hostkey mismatch"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

1;
