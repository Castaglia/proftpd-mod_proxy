package ProFTPD::Tests::Modules::mod_proxy::ban;

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
  proxy_ban_reverse_max_login_attempts => {
    order => ++$order,
    test_class => [qw(forking mod_ban reverse)],
  },

  proxy_ban_forward_noproxyauth_max_login_attempts => {
    order => ++$order,
    test_class => [qw(forking forward mod_ban)],
  },

  proxy_ban_forward_userwithproxyauth_max_login_attempts => {
    order => ++$order,
    test_class => [qw(forking forward mod_ban)],
  },

  proxy_ban_forward_proxyuserwithproxyauth_max_login_attempts => {
    order => ++$order,
    test_class => [qw(forking forward mod_ban)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub get_forward_proxy_config {
  my $tmpdir = shift;
  my $log_file = shift;
  my $vhost_port = shift;

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/proxy");

  my $config = {
    ProxyEngine => 'on',
    ProxyLog => $log_file,
    ProxyRole => 'forward',
    ProxyTables => $table_dir,

    Class => {
      'forward-proxy' => {
        From => '127.0.0.1',
        ProxyForwardEnabled => 'on',
      },
    },
  };

  return $config;
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

sub proxy_ban_reverse_max_login_attempts {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyTimeoutConnect} = '1sec';

  my $ban_tab = File::Spec->rel2abs("$tmpdir/ban.tab");
  my $timeout_idle = 10;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 event:10 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.reverse:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',

    MaxLoginAttempts => 2,

    IfModules => {
      'mod_ban.c' => {
        BanEngine => 'on',
        BanLog => $setup->{log_file},

        # This says to ban a client which exceeds the MaxLoginAttempts
        # limit once within the last 1 minute will be banned for 5 secs
        BanOnEvent => 'MaxLoginAttempts 1/00:01:00 00:00:05',

        BanTable => $ban_tab,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      for (my $i = 0; $i < 2; $i++) {
        eval { $client->login($setup->{user}, 'foo') };
        unless ($@) {
          die("Login succeeded unexpectedly");
        }

        my $resp_code = $client->response_code();
        my $resp_msg = $client->response_msg();

        my $expected = 530;
        $self->assert($expected == $resp_code,
          test_msg("Expected response code $expected, got $resp_code"));

        $expected = "Login incorrect.";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected response message '$expected', got '$resp_msg'"));
      }

      # Now try again with the correct info; we should be banned.  Note
      # that we have to create a separate connection for this.

      eval { $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port,
        undef, 0) };
      unless ($@) {
        die("Connect succeeded unexpectedly");
      }

      my $conn_ex = ProFTPD::TestSuite::FTP::get_connect_exception();
      my $expected = "";
      $self->assert($expected eq $conn_ex,
        test_msg("Expected exception '$expected', got '$conn_ex'"));
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

sub proxy_ban_forward_noproxyauth_max_login_attempts {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 17;

  my $proxy_config = get_forward_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyForwardMethod} = 'user@host';

  my $ban_tab = File::Spec->rel2abs("$tmpdir/ban.tab");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.forward:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    ServerIdent => 'on "Forward Proxy Server"',
    SocketBindTight => 'on',

    MaxLoginAttempts => 2,

    IfModules => {
      'mod_ban.c' => {
        BanEngine => 'on',
        BanLog => $setup->{log_file},

        # This says to ban a client which exceeds the MaxLoginAttempts
        # limit once within the last 1 minute will be banned for 5 secs
        BanOnEvent => 'MaxLoginAttempts 1/00:01:00 00:00:05',

        BanTable => $ban_tab,
      },

      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      for (my $i = 0; $i < 2; $i++) {
        eval { $client->login("$setup->{user}\@127.0.0.1:$vhost_port", 'foo') };
        unless ($@) {
          die("Login succeeded unexpectedly");
        }

        my $resp_code = $client->response_code();
        my $resp_msg = $client->response_msg();

        my $expected = 530;
        $self->assert($expected == $resp_code,
          test_msg("Expected response code $expected, got $resp_code"));

        $expected = "Login incorrect.";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected response message '$expected', got '$resp_msg'"));
      }

      # Now try again with the correct info; we should be banned.  Note
      # that we have to create a separate connection for this.

      eval { $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port,
        undef, 0) };
      unless ($@) {
        die("Connect succeeded unexpectedly");
      }

      my $conn_ex = ProFTPD::TestSuite::FTP::get_connect_exception();
      my $expected = "";
      $self->assert($expected eq $conn_ex,
        test_msg("Expected exception '$expected', got '$conn_ex'"));
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

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_ban_forward_userwithproxyauth_max_login_attempts {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  # Have separate Auth files for the proxy
  my $proxy_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $proxy_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $proxy_user = 'proxy-user';
  my $proxy_passwd = 'proxy-test';

  auth_user_write($proxy_user_file, $proxy_user, $proxy_passwd,
    $setup->{uid}, $setup->{gid}, $setup->{home_dir}, '/bin/bash');
  auth_group_write($proxy_group_file, $setup->{group}, $setup->{gid},
    $proxy_user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 17;

  my $proxy_config = get_forward_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyForwardMethod} = 'proxyuser,user@host';

  my $ban_tab = File::Spec->rel2abs("$tmpdir/ban.tab");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.forward:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $proxy_user_file,
    AuthGroupFile => $proxy_group_file,
    ServerIdent => 'on "Forward Proxy Server"',
    SocketBindTight => 'on',

    # Whether the login attempt is to the proxy or to the real server,
    # the same number of login attempts is enforced; it's an overall total.
    MaxLoginAttempts => 2,

    IfModules => {
      'mod_ban.c' => {
        BanEngine => 'on',
        BanLog => $setup->{log_file},

        # This says to ban a client which exceeds the MaxLoginAttempts
        # limit once within the last 1 minute will be banned for 5 secs
        BanOnEvent => 'MaxLoginAttempts 1/00:01:00 00:00:05',

        BanTable => $ban_tab,
      },

      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      for (my $i = 0; $i < 2; $i++) {
        eval { $client->login($proxy_user, 'foo') };
        unless ($@) {
          die("Login succeeded unexpectedly");
        }

        my $resp_code = $client->response_code();
        my $resp_msg = $client->response_msg();

        my $expected = 530;
        $self->assert($expected == $resp_code,
          test_msg("Expected response code $expected, got $resp_code"));

        $expected = "Login incorrect.";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected response message '$expected', got '$resp_msg'"));
      }

      # Now try again with the correct info; we should be banned.  Note
      # that we have to create a separate connection for this.

      eval { $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port,
        undef, 0) };
      unless ($@) {
        die("Connect succeeded unexpectedly");
      }

      my $conn_ex = ProFTPD::TestSuite::FTP::get_connect_exception();
      my $expected = "";
      $self->assert($expected eq $conn_ex,
        test_msg("Expected exception '$expected', got '$conn_ex'"));
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

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_ban_forward_proxyuserwithproxyauth_max_login_attempts {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  # Have separate Auth files for the proxy
  my $proxy_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $proxy_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $proxy_user = 'proxy-user';
  my $proxy_passwd = 'proxy-test';

  auth_user_write($proxy_user_file, $proxy_user, $proxy_passwd,
    $setup->{uid}, $setup->{gid}, $setup->{home_dir}, '/bin/bash');
  auth_group_write($proxy_group_file, $setup->{group}, $setup->{gid},
    $proxy_user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 17;

  my $proxy_config = get_forward_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyForwardMethod} = 'proxyuser@host,user';

  my $ban_tab = File::Spec->rel2abs("$tmpdir/ban.tab");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.forward:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $proxy_user_file,
    AuthGroupFile => $proxy_group_file,
    ServerIdent => 'on "Forward Proxy Server"',
    SocketBindTight => 'on',

    # Whether the login attempt is to the proxy or to the real server,
    # the same number of login attempts is enforced; it's an overall total.
    MaxLoginAttempts => 2,

    IfModules => {
      'mod_ban.c' => {
        BanEngine => 'on',
        BanLog => $setup->{log_file},

        # This says to ban a client which exceeds the MaxLoginAttempts
        # limit once within the last 1 minute will be banned for 5 secs
        BanOnEvent => 'MaxLoginAttempts 1/00:01:00 00:00:05',

        BanTable => $ban_tab,
      },

      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      for (my $i = 0; $i < 2; $i++) {
        eval { $client->login("$proxy_user\@127.0.0.1:$vhost_port", 'foo') };
        unless ($@) {
          die("Login succeeded unexpectedly");
        }

        my $resp_code = $client->response_code();
        my $resp_msg = $client->response_msg();

        my $expected = 530;
        $self->assert($expected == $resp_code,
          test_msg("Expected response code $expected, got $resp_code"));

        $expected = "Login incorrect.";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected response message '$expected', got '$resp_msg'"));
      }

      # Now try again with the correct info; we should be banned.  Note
      # that we have to create a separate connection for this.

      eval { $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port,
        undef, 0) };
      unless ($@) {
        die("Connect succeeded unexpectedly");
      }

      my $conn_ex = ProFTPD::TestSuite::FTP::get_connect_exception();
      my $expected = "";
      $self->assert($expected eq $conn_ex,
        test_msg("Expected exception '$expected', got '$conn_ex'"));
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

  test_cleanup($setup->{log_file}, $ex);
}

1;
