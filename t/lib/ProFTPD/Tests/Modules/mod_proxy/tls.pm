package ProFTPD::Tests::Modules::mod_proxy::tls;

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
  proxy_reverse_frontend_tls_login => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_frontend_tls_login_failed => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_frontend_tls_login_tlslogin => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_frontend_tls_list_pasv => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_backend_tls_login => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_backend_tls_login_cached_session => {
    order => ++$order,
    test_class => [qw(forking mod_tls mod_tls_shmcache reverse)],
  },

  proxy_reverse_backend_tls_login_client_auth => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_backend_tls_login_psk => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_backend_tls_login_failed_unknown_ca => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_backend_tls_login_failed_missing_client_auth => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_backend_tls_list_pasv => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_frontend_backend_tls_roundrobin_login_after_host => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_frontend_backend_tls_list_pasv => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_config_backend_tls_engine_auto_unavail => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_config_backend_tls_engine_auto_ftps_uri_unavail => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_config_backend_tls_engine_on_unavail => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_config_backend_tls_connect_policy_per_user => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_config_backend_tls_connect_policy_per_user_failed_unknown_ca => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_config_backend_tls_verify_server_off => {
    order => ++$order,
    test_class => [qw(forking mod_tls reverse)],
  },

  proxy_reverse_config_backend_tls_no_session_cache => {
    order => ++$order,
    test_class => [qw(forking mod_tls mod_tls_shmcache reverse)],
  },

  proxy_forward_frontend_tls_noproxyauth_login => {
    order => ++$order,
    test_class => [qw(forking mod_tls forward)],
  },

  proxy_forward_backend_tls_login => {
    order => ++$order,
    test_class => [qw(forking mod_tls forward)],
  },

  proxy_forward_backend_tls_login_failed_unknown_ca => {
    order => ++$order,
    test_class => [qw(forking mod_tls forward)],
  },

  proxy_forward_backend_tls_list_pasv => {
    order => ++$order,
    test_class => [qw(forking mod_tls forward)],
  },

  proxy_forward_frontend_backend_tls_login_after_host => {
    order => ++$order,
    test_class => [qw(forking mod_tls forward)],
  },

  proxy_forward_frontend_backend_tls_list_pasv => {
    order => ++$order,
    test_class => [qw(forking mod_tls forward)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
#  return testsuite_get_runnable_tests($TESTS);
# These tests all appear to exhibit similar symptoms; they do not receive the
# 226 response from the backend server for the LIST command.
#    proxy_reverse_config_backend_tls_connect_policy_per_user
#    proxy_reverse_config_backend_tls_verify_server_off
#    proxy_forward_backend_tls_list_pasv
  return qw(
    proxy_reverse_backend_tls_list_pasv
  );

#  return qw(
#    proxy_reverse_frontend_backend_tls_roundrobin_login_after_host
#  );
#    proxy_reverse_frontend_backend_tls_peruser_login_after_host
#    proxy_forward_frontend_backend_tls_login_after_host
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  my $psk_file = File::Spec->rel2abs('t/etc/modules/mod_tls/psk.dat');

  unless (chmod(0400, $psk_file)) {
    die("Can't set perms on $psk_file: $!");
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
    ProxyReverseServers => "ftp://127.0.0.1:$vhost_port",
    ProxyRole => 'reverse',
    ProxyTables => $table_dir,
  };

  return $config;
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

sub proxy_reverse_frontend_tls_login {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $log_file,
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);
 
      my $client_opts = {
        Encryption => 'E',
        Port => $port,
      };

      if ($ENV{TEST_VERBOSE}) {
        $client_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$client_opts);

      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->login($user, $passwd)) {
        die("Can't login: " . $client->last_message());
      }

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_frontend_tls_login_failed {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $log_file,
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);
 
      my $client_opts = {
        Encryption => 'E',
        Port => $port,
      };

      if ($ENV{TEST_VERBOSE}) {
        $client_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$client_opts);

      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      if ($client->login($user, 'foobar')) {
        die("Login succeeded unexpectedly");
      }

      my $resp_msg = $client->last_message();
      $client->quit();

      my $expected = '530 Login incorrect.';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_frontend_tls_login_tlslogin {
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

  my $server_cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $client_cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/client-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);

  my $tlslogin_file = File::Spec->rel2abs("$tmpdir/.tlslogin");
  unless (copy($client_cert_file, $tlslogin_file)) {
    die("Can't copy $client_cert_file to $tlslogin_file: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 auth:10 tls:20 proxy:20 proxy.conn:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $log_file,
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $server_cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'AllowDotLogin',
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);

      # IO::Socket::SSL options
      my $ssl_opts = {
        SSL_use_cert => 1,
        SSL_cert_file => $client_cert_file,
        SSL_key_file => $client_cert_file,
        SSL_ca_file => $ca_file,
      };
 
      my $client_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_Client_Certificate => $ssl_opts,
      };

      if ($ENV{TEST_VERBOSE}) {
        $client_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$client_opts);

      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->_user($user)) {
        die("USER error: " . $client->last_message());
      }

      my $resp_msg = $client->last_message();
      $client->quit();

      # Even though we configured mod_tls on the proxy to allow .tlslogin,
      # mod_proxy does not actually invoke that functionality.  And for good
      # reason.  If mod_tls/mod_proxy allowed the DotLogin, then the client
      # would not need to send a password.  But the backend FTP session is NOT
      # configured for DotLogin, which means that that WILL need a password.
      #
      # Thus expecting the 331 response code here is correct.
      my $expected = "331 Password required for $user";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_frontend_tls_list_pasv {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 netio:20 scoreboard:0 signal:0 proxy:20 proxy.inet:20 proxy.netio:20 proxy.reverse:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $log_file,
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'NoSessionReuseRequired EnableDiags',
        TLSTimeoutHandshake => 5,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        SSL_ca_file => $ca_file,
      };

      my $client_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_Client_Certificate => $ssl_opts,
      };

      if ($ENV{TEST_VERBOSE}) {
        $client_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$client_opts);

      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->login($user, $passwd)) {
        die("Can't login: " . $client->last_message());
      }

      my $res = $client->list();
      unless ($res) {
        die("LIST failed unexpectedly: " . $client->last_message() .
          "(" . IO::Socket::SSL::errstr() . ")");
      }
 
      my $resp_msg = $client->last_message();
      $client->quit();

      my $expected = '226 Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, 20) };
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

sub proxy_reverse_backend_tls_login {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
    TLSOptions EnableDiags
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

# TODO: Note that this test is used for manually reviewing the generated logs;
# it does NOT currently fail if session caching fails (although it should).
sub proxy_reverse_backend_tls_login_cached_session {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');
  my $cache_file = File::Spec->rel2abs("$tmpdir/tls-shmcache.dat");

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls_shmcache.c' => {
        TLSSessionCache => "shm:/file=$cache_file",
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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      for (my $i = 0; $i < 3; $i++) {
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
        $client->login($user, $passwd);
        $client->quit();
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_backend_tls_login_client_auth {
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

  my $client_cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/client-cert.pem');
  my $server_cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;
  $proxy_config->{ProxyTLSCertificateFile} = $client_cert_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $server_cert_file
    TLSCACertificateFile $ca_file
    TLSVerifyClient on
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_backend_tls_login_psk {
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

  my $client_cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/client-cert.pem');
  my $server_cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');
  my $psk_file = File::Spec->rel2abs('t/etc/modules/mod_tls/psk.dat');
  my $psk_id = "proxy";

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;
  $proxy_config->{ProxyTLSCertificateFile} = $client_cert_file;
  $proxy_config->{ProxyTLSCipherSuite} = "PSK";
  $proxy_config->{ProxyTLSPreSharedKey} = "$psk_id hex:$psk_file";

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $server_cert_file
    TLSCACertificateFile $ca_file
    TLSCipherSuite PSK
    TLSPreSharedKey $psk_id hex:$psk_file
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_backend_tls_login_failed_unknown_ca {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      eval { ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 0) };
      unless ($@) {
        die("Connect succeeded unexpectedly");
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_backend_tls_login_failed_missing_client_auth {
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

  my $client_cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/client-cert.pem');
  my $server_cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;
#  $proxy_config->{ProxyTLSCertificateFile} = $client_cert_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $server_cert_file
    TLSCACertificateFile $ca_file
    TLSVerifyClient on
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      eval { ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 0) };
      unless ($@) {
        die("Connection succeeded unexpectedly");
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_backend_tls_list_pasv {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:10 lock:0 netio:20 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.reverse:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
    TLSOptions EnableDiags
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->list_raw();
      unless ($conn) {
        die("Failed to LIST: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 5);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, 20) };
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

sub proxy_reverse_frontend_backend_tls_list_pasv {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 netio:20 scoreboard:0 signal:0 proxy:20 proxy.netio:20 proxy.db:20 proxy.reverse:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $log_file,
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'NoCertRequest NoSessionReuseRequired EnableDiags',
        TLSTimeoutHandshake => 5,
        TLSVerifyClient => 'off',
        TLSVerifyServer => 'off',
      },

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file

    TLSVerifyClient off
    TLSVerifyServer off
    TLSOptions EnableDiags NoCertRequest NoSessionReuseRequired
  </IfModule>
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        SSL_verify_mode => $IO::Socket::SSL::SSL_VERIFY_NONE,
      };

      my $client_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_Client_Certificate => $ssl_opts,
      };

      if ($ENV{TEST_VERBOSE}) {
        $client_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$client_opts);

      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->login($user, $passwd)) {
        die("Can't login: " . $client->last_message());
      }

      my $res = $client->list();
      unless ($res) {
        die("LIST failed unexpectedly: " . $client->last_message() .
          "(" . IO::Socket::SSL::errstr() . ")");
      }
 
      my $resp_msg = $client->last_message();
      my $expected = '226 Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response '$expected', got '$resp_msg'"));

      # Do the LIST again; there are some reports that a first transfer
      # might succeed, but subsequent ones will fail.
      $res = $client->list();
      unless ($res) {
        die("LIST failed unexpectedly: " . $client->last_message() .
          "(" . IO::Socket::SSL::errstr() . ")");
      }

      $resp_msg = $client->last_message();
      $client->quit();

      $expected = '226 Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, 20) };
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

sub proxy_reverse_config_backend_tls_engine_auto_unavail {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none
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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_config_backend_tls_engine_auto_ftps_uri_unavail {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);

  # Note: deliberately use a URI here with the 'ftps' scheme, to indicate
  # that FTPS is REQUIRED for that server.
  $proxy_config->{ProxyReverseServers} = "ftps://127.0.0.1:$vhost_port";
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none
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
      # Give the server a chance to start up
      sleep(2);

      eval { ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 0) };
      unless ($@) {
        die("Connection succeeded unexpectedly");
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_config_backend_tls_engine_on_unavail {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'on';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none
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
      # Give the server a chance to start up
      sleep(2);

      eval { ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 0) };
      unless ($@) {
        die("Connection succeeded unexpectedly");
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_reverse_config_backend_tls_connect_policy_per_user {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;
  $proxy_config->{ProxyRetryCount} = 1;
  $proxy_config->{ProxyTimeoutConnect} = '2sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerUser';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port2";
  my $nbackends = 2;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 response:20 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.reverse:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TransferLog none
  WtmpLog off

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      for (my $i = 0; $i < $nbackends+1; $i++) {
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
    eval { server_wait($config_file, $rfh, 15) };
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

sub proxy_reverse_config_backend_tls_connect_policy_per_user_failed_unknown_ca {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyRetryCount} = 1;
  $proxy_config->{ProxyTimeoutConnect} = '2sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerUser';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port2";

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 response:20 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.reverse:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TransferLog none
  WtmpLog off

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 0);
      eval { $client->login($user, $passwd) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 530;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Login incorrect.';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, 15) };
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

sub proxy_reverse_config_backend_tls_verify_server_off {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSVerifyServer} = 'off';
  $proxy_config->{ProxyRetryCount} = 1;
  $proxy_config->{ProxyTimeoutConnect} = '2sec';
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerUser';
  $proxy_config->{ProxyReverseServers} = "ftp://127.0.0.1:$vhost_port ftp://127.0.0.1:$vhost_port2";

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 response:20 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.reverse:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  TransferLog none
  WtmpLog off

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 0);
      $client->login($user, $passwd);
      ftp_list($self, $client);
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh, 15) };
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

# TODO: Note that this test is used for manually reviewing the generated logs;
# it does NOT currently fail if session caching fails (although it should).
sub proxy_reverse_config_backend_tls_no_session_cache {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');
  my $cache_file = File::Spec->rel2abs("$tmpdir/tls-shmcache.dat");

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyTLSEngine} = 'auto';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'NoSessionCache EnableDiags';
  } else {
    $proxy_config->{ProxyTLSOptions} = 'NoSessionCache';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.db:20 proxy.netio:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 proxy.ftp.sess:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls_shmcache.c' => {
        TLSSessionCache => "shm:/file=$cache_file",
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
<VirtualHost 127.0.0.1>
  Port $vhost_port
  ServerName "Real Server"

  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file
  AuthOrder mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
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
      # Give the server a chance to start up
      sleep(2);

      for (my $i = 0; $i < 3; $i++) {
        my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
        $client->login($user, $passwd);
        $client->quit();
      }
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_forward_frontend_tls_noproxyauth_login {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 17;

  my $proxy_config = get_forward_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyForwardMethod} = 'user@host';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.forward:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $log_file,
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);

      my $client_opts = {
        Encryption => 'E',
        Port => $port,
      };

      if ($ENV{TEST_VERBOSE}) {
        $client_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$client_opts);

      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->login("$user\@127.0.0.1:$vhost_port", $passwd)) {
        die("Can't login: " . $client->last_message());
      }

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_forward_backend_tls_login {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 17;

  my $proxy_config = get_forward_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyForwardMethod} = 'user@host';
  $proxy_config->{ProxyTLSEngine} = 'on';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;
  $proxy_config->{ProxyRetryCount} = 1;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.forward:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login("$user\@127.0.0.1:$vhost_port", $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_forward_backend_tls_login_failed_unknown_ca {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 17;

  my $proxy_config = get_forward_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyForwardMethod} = 'user@host';
  $proxy_config->{ProxyTLSEngine} = 'on';
  $proxy_config->{ProxyRetryCount} = 1;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.forward:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      eval { $client->login("$user\@127.0.0.1:$vhost_port", $passwd) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 530;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Unable to connect to 127.0.0.1:$vhost_port: Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_forward_backend_tls_list_pasv {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 17;

  my $proxy_config = get_forward_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyForwardMethod} = 'user@host';
  $proxy_config->{ProxyTLSEngine} = 'on';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;
  $proxy_config->{ProxyRetryCount} = 1;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.forward:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login("$user\@127.0.0.1:$vhost_port", $passwd);
      ftp_list($self, $client);
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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

sub proxy_forward_frontend_backend_tls_list_pasv {
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

  my $cert_file = File::Spec->rel2abs('t/etc/modules/mod_tls/server-cert.pem');
  my $ca_file = File::Spec->rel2abs('t/etc/modules/mod_tls/ca-cert.pem');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 17;

  my $proxy_config = get_forward_proxy_config($tmpdir, $log_file, $vhost_port);
  $proxy_config->{ProxyForwardMethod} = 'user@host';
  $proxy_config->{ProxyTLSEngine} = 'on';
  $proxy_config->{ProxyTLSCACertificateFile} = $ca_file;
  $proxy_config->{ProxyRetryCount} = 1;

  if ($ENV{TEST_VERBOSE}) {
    $proxy_config->{ProxyTLSOptions} = 'EnableDiags';
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10 event:0 lock:0 scoreboard:0 signal:0 proxy:20 proxy.forward:20 proxy.tls:20 proxy.ftp.conn:20 proxy.ftp.ctrl:20 proxy.ftp.data:20 proxy.ftp.msg:20 tls:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $log_file,
        TLSProtocol => 'SSLv3 TLSv1',
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'NoSessionReuseRequired EnableDiags',
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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
  WtmpLog off
  TransferLog none

  <IfModule mod_tls.c>
    TLSEngine on
    TLSLog $log_file
    TLSProtocol SSLv3 TLSv1
    TLSRequired on
    TLSRSACertificateFile $cert_file
    TLSCACertificateFile $ca_file
  </IfModule>
</VirtualHost>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  require Net::FTPSSL;

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
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        SSL_ca_file => $ca_file,
      };

      my $client_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_Client_Certificate => $ssl_opts,
      };

      if ($ENV{TEST_VERBOSE}) {
        $client_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$client_opts);

      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->login("$user\@127.0.0.1:$vhost_port", $passwd)) {
        die("Can't login: " . $client->last_message());
      }

      my $res = $client->list();
      unless ($res) {
        die("LIST failed unexpectedly: " . $client->last_message() .
          "(" . IO::Socket::SSL::errstr() . ")");
      }

      my $resp_msg = $client->last_message();
      $client->quit();

      my $expected = '226 Transfer complete';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response '$expected', got '$resp_msg'"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
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
