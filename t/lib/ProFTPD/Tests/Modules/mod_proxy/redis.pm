package ProFTPD::Tests::Modules::mod_proxy::redis;

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
  proxy_reverse_config_redis_connect_policy_random => {
    order => ++$order,
    test_class => [qw(forking mod_redis reverse)],
  },

  proxy_reverse_config_redis_connect_policy_shuffle => {
    order => ++$order,
    test_class => [qw(forking mod_redis reverse)],
  },

  proxy_reverse_config_redis_connect_policy_roundrobin => {
    order => ++$order,
    test_class => [qw(forking mod_redis reverse)],
  },

  # This is flaky when run in GitHub workflows, but passes when run in Docker
  # locally.  So marking it as flaky.
  proxy_reverse_config_redis_connect_policy_leastconns => {
    order => ++$order,
    test_class => [qw(flaky forking mod_redis reverse)],
  },

  proxy_reverse_config_redis_connect_policy_leastresponsetime => {
    order => ++$order,
    test_class => [qw(forking mod_redis reverse)],
  },

  proxy_reverse_config_redis_connect_policy_per_host => {
    order => ++$order,
    test_class => [qw(forking mod_ifsession mod_redis reverse)],
  },

  proxy_reverse_config_redis_connect_policy_per_user => {
    order => ++$order,
    test_class => [qw(forking mod_redis reverse)],
  },

  proxy_reverse_config_redis_connect_policy_per_user_by_json => {
    order => ++$order,
    test_class => [qw(forking mod_redis reverse)],
  },

  proxy_reverse_config_redis_connect_policy_per_group => {
    order => ++$order,
    test_class => [qw(forking mod_redis reverse)],
  },

  proxy_reverse_config_redis_connect_policy_per_group_by_json => {
    order => ++$order,
    test_class => [qw(forking mod_redis reverse)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub config_hash2array {
  my $hash = shift;

  my $array = [];

  foreach my $key (keys(%$hash)) {
    push(@$array, "$key $hash->{$key}\n");
  }

  return $array;
}

sub get_redis_config {
  my $log_file = shift;

  my $redis_server = '127.0.0.1';
  if (defined($ENV{REDIS_HOST})) {
    $redis_server = $ENV{REDIS_HOST};
  }

  my $config = {
    RedisEngine => 'on',
    RedisLog => $log_file,
    RedisServer => "$redis_server:6379",
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
    ProxyDatastore => 'Redis 127.0.0.1.',
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
    "Expected response code $expected, got $resp_code");

  $expected = 'Goodbye.';
  $self->assert($expected eq $resp_msg,
    "Expected response message '$expected', got '$resp_msg'");

  1;
}

sub proxy_reverse_config_redis_connect_policy_random {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'Random';

  # For now, we cheat and simply repeat the same vhost three times
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port";
  my $nbackends = 3;

  my $redis_config = get_redis_config($log_file);

  my $timeout_idle = 10;

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.reverse:20 proxy.reverse.redis:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },

    Limit => {
      LOGIN => {
        DenyUser => $user,
      },
    },

  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1, 1);
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub proxy_reverse_config_redis_connect_policy_shuffle {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'Shuffle';

  # For now, we cheat and simply repeat the same vhost three times
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port";
  my $nbackends = 3;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($log_file);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.reverse:20 proxy.reverse.redis:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },

    Limit => {
      LOGIN => {
        DenyUser => $user,
      },
    },

  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1, 1);
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub proxy_reverse_config_redis_connect_policy_roundrobin {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'RoundRobin';

  # For now, we cheat and simply repeat the same vhost three times
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port";
  my $nbackends = 3;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($log_file);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.reverse:20 proxy.reverse.redis:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },

    Limit => {
      LOGIN => {
        DenyUser => $user,
      },
    },

  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1, 1);
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub proxy_reverse_config_redis_connect_policy_leastconns {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'LeastConns';

  # For now, we cheat and simply repeat the same vhost three times
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port";
  my $nbackends = 3;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($setup->{log_file});

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.reverse:20 proxy.reverse.redis:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
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
  RootLogin on
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
      # Allow server to start up
      sleep(2);

      for (my $i = 0; $i < $nbackends+1; $i++) {
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1, 2);
        $client->login($setup->{user}, $setup->{passwd});
        ftp_list($self, $client);
        sleep(1);
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

sub proxy_reverse_config_redis_connect_policy_leastresponsetime {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'LeastResponseTime';

  # For now, we cheat and simply repeat the same vhost three times
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port";
  my $nbackends = 3;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($log_file);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.reverse:20 proxy.reverse.redis:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 redis:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },

    Limit => {
      LOGIN => {
        DenyUser => $user,
      },
    },

  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub proxy_reverse_config_redis_connect_policy_per_host {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTimeoutConnect} = '1sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerHost';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port2";
  my $nbackends = 2;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($log_file);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.reverse:20 proxy.reverse.redis:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },

    Limit => {
      LOGIN => {
        DenyUser => $user,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub proxy_reverse_config_redis_connect_policy_per_user {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTimeoutConnect} = '1sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerUser';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port2";
  my $nbackends = 2;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($log_file);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.reverse:20 proxy.reverse.redis:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },

    Limit => {
      LOGIN => {
        DenyUser => $user,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub proxy_reverse_config_redis_connect_policy_per_user_by_json {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTimeoutConnect} = '1sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerUser';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port";

  my $user_path = File::Spec->rel2abs("$tmpdir/$user-servers.json");
  if (open(my $fh, "> $user_path")) {
    print $fh "[ \"ftp://127.0.0.1:$vhost_port2\" ]\n";
    unless (close($fh)) {
      die("Can't write $user_path: $!");
    }

  } else {
    die("Can't open $user_path: $!");
  }

  my $uservar_path = File::Spec->rel2abs("$tmpdir/%U-servers.json");

  # Since we need multiple ProxyReverseServers directives, convert this
  # hashref into an arrayref.
  $proxy_config = config_hash2array($proxy_config);

  push(@$proxy_config, "ProxyReverseServers file:$uservar_path");
  my $nbackends = 1;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($log_file);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.reverse:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },

    Limit => {
      LOGIN => {
        DenyUser => $user,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub proxy_reverse_config_redis_connect_policy_per_group {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTimeoutConnect} = '1sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerGroup';
  $proxy_config->{ProxyOptions} = 'UseReverseProxyAuth';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port2";
  my $nbackends = 2;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($log_file);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.reverse:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub proxy_reverse_config_redis_connect_policy_per_group_by_json {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/proxy.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/proxy.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/proxy.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/proxy.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/proxy.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTimeoutConnect} = '1sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerGroup';
  $proxy_config->{ProxyOptions} = 'UseReverseProxyAuth';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port";

  my $group_path = File::Spec->rel2abs("$tmpdir/$group-servers.json");
  if (open(my $fh, "> $group_path")) {
    print $fh "[ \"ftp://127.0.0.1:$vhost_port2\" ]\n";
    unless (close($fh)) {
      die("Can't write $group_path: $!");
    }

  } else {
    die("Can't open $group_path: $!");
  }

  my $groupvar_path = File::Spec->rel2abs("$tmpdir/%g-servers.json");

  # Since we need multiple ProxyReverseServers directives, convert this
  # hashref into an arrayref.
  $proxy_config = config_hash2array($proxy_config);

  push(@$proxy_config, "ProxyReverseServers file:$groupvar_path");
  my $nbackends = 1;

  my $timeout_idle = 10;

  my $redis_config = get_redis_config($log_file);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.reverse:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_proxy.c' => $proxy_config,
      'mod_redis.c' => $redis_config,
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TimeoutIdle $timeout_idle

  TransferLog none
  WtmpLog off
</VirtualHost>

EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
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
        $client->login($user, $passwd);
        ftp_list($self, $client);
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, $timeout_idle + 2) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

1;
