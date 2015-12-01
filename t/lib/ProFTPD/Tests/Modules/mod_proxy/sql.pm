package ProFTPD::Tests::Modules::mod_proxy::sql;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  proxy_sql_reverse_config_connect_policy_per_user_by_sql => {
    order => ++$order,
    test_class => [qw(forking mod_sql_sqlite reverse)],
  },

  proxy_sql_reverse_config_connect_policy_per_group_by_sql => {
    order => ++$order,
    test_class => [qw(forking mod_sql_sqlite reverse)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub build_db {
  my $cmd = shift;
  my $db_script = shift;
  my $check_exit_status = shift;
  $check_exit_status = 0 unless defined $check_exit_status;

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Executing sqlite3: $cmd\n";
  }

  my @output = `$cmd`;
  my $exit_status = $?;

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Output: ", join('', @output), "\n";
  }

  if ($check_exit_status) {
    if ($? != 0) {
      croak("'$cmd' failed");
    }
  }

  unlink($db_script);
  return 1;
}

sub config_hash2array {
  my $hash = shift;

  my $array = [];

  foreach my $key (keys(%$hash)) {
    push(@$array, "$key $hash->{$key}\n");
  }

  return $array;
}

sub get_reverse_proxy_config {
  my $tmpdir = shift;
  my $log_file = shift;
  my $vhost_port = shift;

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/proxy");

  my $config = {
    ProxyEngine => 'on',
    ProxyLog => $log_file,
    ProxyReverseServers => "ftp://127.0.0.1:$vhost_port",
    ProxyRole => 'reverse',
    ProxyTables => $table_dir,
  };

  return $config;
}

sub ftp_list {
  my $self = shift;
  my $client = shift;

  my $conn = $client->list_raw();
  unless ($conn) {
    die("Failed to LIST: " . $client->response_code() . ' ' .
      $client->response_msg());
  }

  my $buf;
  $conn->read($buf, 8192, 10);
  eval { $conn->close() };

  my $resp_code = $client->response_code();
  my $resp_msg = $client->response_msg();
  $self->assert_transfer_ok($resp_code, $resp_msg);

  ($resp_code, $resp_msg) = $client->quit();
  my $expected = 221;
  $self->assert($expected == $resp_code,
    test_msg("Expected response code $expected, got $resp_code"));

  $expected = 'Goodbye.';
  $self->assert($expected eq $resp_msg,
    test_msg("Expected response message '$expected', got '$resp_msg'"));

  1;
}

sub proxy_sql_reverse_config_connect_policy_per_user_by_sql {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyTimeoutConnect} = '1sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerUser';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port";

  # Since we need multiple ProxyReverseServers directives, convert this
  # hashref into an arrayref.
  $proxy_config = config_hash2array($proxy_config);

  push(@$proxy_config, "ProxyReverseServers sql:/get-user-servers");
  my $nbackends = 1;

  my $db_file = File::Spec->rel2abs("$tmpdir/proftpd.db");

  # Build up the sqlite3 command to create tables and populate them
  my $db_script = File::Spec->rel2abs("$tmpdir/proftpd.sql");
  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE proxy_user_servers (
  user_name TEXT PRIMARY KEY,
  url TEXT
);

INSERT INTO proxy_user_servers (user_name, url) VALUES ('$setup->{user}', 'ftp://127.0.0.1:$vhost_port2');

EOS
    unless (close($fh)) {
      die("Can't write $db_script: $!");
    }

  } else {
    die("Can't open $db_script: $!");
  }

  my $cmd = "sqlite3 $db_file < $db_script";
  build_db($cmd, $db_script);

  # Make sure that, if we're running as root, the database file has
  # the permissions/privs set for use by proftpd
  if ($< == 0) {
    unless (chmod(0666, $db_file)) {
      die("Can't set perms on $db_file to 0666: $!");
    }
  }

  my $timeout_idle = 10;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.reverse:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,

      'mod_sql.c' => {
        SQLEngine => 'log',
        SQLBackend => 'sqlite3',
        SQLConnectInfo => $db_file,
        SQLLogFile => $setup->{log_file},
        SQLNamedQuery => 'get-user-servers SELECT "url FROM proxy_user_servers WHERE user_name = %{0}"',
      }
    },

    Limit => {
      LOGIN => {
        DenyUser => $setup->{user},
      },
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
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $setup->{auth_user_file}
  AuthGroupFile $setup->{auth_group_file}
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      for (my $i = 0; $i < $nbackends+1; $i++) {
        sleep(2);
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 0);
        $client->login($setup->{user}, $setup->{passwd});
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_sql_reverse_config_connect_policy_per_group_by_sql {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyTimeoutConnect} = '1sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerGroup';
  $proxy_config->{ProxyOptions} = 'UseReverseProxyAuth';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port";

  # Since we need multiple ProxyReverseServers directives, convert this
  # hashref into an arrayref.
  $proxy_config = config_hash2array($proxy_config);

  push(@$proxy_config, "ProxyReverseServers sql:/get-group-servers");
  my $nbackends = 1;

  my $db_file = File::Spec->rel2abs("$tmpdir/proftpd.db");

  # Build up the sqlite3 command to create tables and populate them
  my $db_script = File::Spec->rel2abs("$tmpdir/proftpd.sql");
  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE proxy_group_servers (
  group_name TEXT PRIMARY KEY,
  url TEXT
);

INSERT INTO proxy_group_servers (group_name, url) VALUES ('$setup->{group}', 'ftp://127.0.0.1:$vhost_port2');

EOS
    unless (close($fh)) {
      die("Can't write $db_script: $!");
    }

  } else {
    die("Can't open $db_script: $!");
  }

  my $cmd = "sqlite3 $db_file < $db_script";
  build_db($cmd, $db_script);

  # Make sure that, if we're running as root, the database file has
  # the permissions/privs set for use by proftpd
  if ($< == 0) {
    unless (chmod(0666, $db_file)) {
      die("Can't set perms on $db_file to 0666: $!");
    }
  }

  my $timeout_idle = 10;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.reverse:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,

      'mod_sql.c' => {
        SQLEngine => 'log',
        SQLBackend => 'sqlite3',
        SQLConnectInfo => $db_file,
        SQLLogFile => $setup->{log_file},
        SQLNamedQuery => 'get-group-servers SELECT "url FROM proxy_group_servers WHERE group_name = %{0}"',
      }
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
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $setup->{auth_user_file}
  AuthGroupFile $setup->{auth_group_file}
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      for (my $i = 0; $i < $nbackends+1; $i++) {
        sleep(2);
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 0);
        $client->login($setup->{user}, $setup->{passwd});
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
