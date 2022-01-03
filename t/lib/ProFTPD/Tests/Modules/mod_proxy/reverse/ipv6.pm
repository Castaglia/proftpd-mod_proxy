package ProFTPD::Tests::Modules::mod_proxy::reverse::ipv6;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Carp;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IO::Socket::INET;
use Net::Address::IP::Local;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  proxy_reverse_ipv6_list_pasv => {
    order => ++$order,
    test_class => [qw(feature_ipv6 forking reverse)],
  },

  proxy_reverse_ipv6_list_port => {
    order => ++$order,
    test_class => [qw(feature_ipv6 forking reverse)],
  },

  proxy_reverse_ipv6_epsv => {
    order => ++$order,
    test_class => [qw(feature_ipv6 forking reverse)],
  },

  proxy_reverse_ipv6_eprt_ipv4 => {
    order => ++$order,
    test_class => [qw(feature_ipv6 forking reverse)],
  },

  proxy_reverse_ipv6_eprt_ipv6 => {
    order => ++$order,
    test_class => [qw(feature_ipv6 forking reverse)],
  },
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub get_reverse_proxy_config {
  my $tmpdir = shift;
  my $log_file = shift;
  my $vhost_port = shift;

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/proxy");

  my $config = {
    ProxyEngine => 'on',
    ProxyLog => $log_file,
    ProxyReverseServers => "ftp://\[::1\]:$vhost_port",
    ProxyRole => 'reverse',
    ProxyTables => $table_dir,
    ProxySourceAddress => '::1',
  };

  return $config;
}

sub proxy_reverse_ipv6_list_pasv {
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

  my $timeout_idle = 10;

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.xfer:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,
    UseIPv6 => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
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
<VirtualHost ::1>
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
      sleep(1);
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($user, $passwd);

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

sub proxy_reverse_ipv6_list_port {
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

  my $timeout_idle = 10;

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.xfer:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,
    UseIPv6 => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
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
<VirtualHost ::1>
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
      sleep(1);
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1, 1);
      $client->login($user, $passwd);

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

sub proxy_reverse_ipv6_epsv {
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

  my $timeout_idle = 10;

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.xfer:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,
    UseIPv6 => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
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
<VirtualHost ::1>
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
      sleep(1);
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($user, $passwd);

      my ($resp_code, $resp_msg) = $client->epsv();

      my $expected = 229;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = '^Entering Extended Passive Mode \(\|\|\|\d+\|\)';
      $self->assert(qr/$expected/, $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
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

sub proxy_reverse_ipv6_eprt_ipv4 {
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

  my $timeout_idle = 10;

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.xfer:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,
    UseIPv6 => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
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
<VirtualHost ::1>
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
      sleep(1);
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($user, $passwd);

      my ($resp_code, $resp_msg) = $client->eprt('|1|127.0.0.1|4856|');

      my $expected;

      $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "EPRT command successful";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client->quit();
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

sub proxy_reverse_ipv6_eprt_ipv6 {
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

  my $timeout_idle = 10;

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.xfer:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',
    TimeoutIdle => $timeout_idle,
    UseIPv6 => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
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
<VirtualHost ::1>
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
      sleep(1);
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($user, $passwd);

      my ($resp_code, $resp_msg) = $client->eprt('|2|::ffff:127.0.0.1|4856|');

      my $expected;

      $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "EPRT command successful";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client->quit();
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
