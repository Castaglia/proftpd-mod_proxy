package ProFTPD::Tests::Modules::mod_proxy::ssh;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Carp;
use Digest::MD5;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IO::Socket::INET;
use IPC::Open3;
use POSIX qw(:fcntl_h);
use Time::HiRes qw(gettimeofday tv_interval usleep);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  proxy_reverse_backend_ssh_connect_bad_version_format => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_connect_timeoutlogin => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_dh_group1_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_dh_group14_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_dh_group14_sha256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_dh_group16_sha512 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_dh_group18_sha512 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_dh_gex_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_dh_gex_sha256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_ecdh_sha2_nistp256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_ecdh_sha2_nistp384 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_ecdh_sha2_nistp521 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_curve25519_sha256 => {
    order => ++$order,
    test_class => [qw(feature_sodium forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_curve448_sha512 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_kex_rsa1024_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostkey_rsa => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostkey_rsa_sha256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostkey_rsa_sha512 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostkey_dss => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostkey_ecdsa256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostkey_ecdsa384 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostkey_ecdsa521 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_hostkey_ed25519 => {
    order => ++$order,
    test_class => [qw(feature_sodium forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_aes256_gcm => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_aes256_ctr => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_aes256_cbc => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_aes192_ctr => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_aes192_cbc => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_aes128_gcm => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_aes128_ctr => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_aes128_cbc => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_blowfish_ctr => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_blowfish_cbc => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_cast128_cbc => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_arcfour256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_arcfour128 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_3des_ctr => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_3des_cbc => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_cipher_none => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_sha1_etm_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_sha1_96 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_sha1_96_etm_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_md5 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_md5_etm_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_md5_96 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_md5_96_etm_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_ripemd160 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_sha256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_sha256_etm_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_sha512 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_hmac_sha512_etm_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_umac64_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_umac64_etm_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_umac128_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_umac128_etm_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_mac_none => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_compress_none => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_compress_zlib => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_compress_zlib_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_none => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_hostbased => {
    order => ++$order,
    test_class => [qw(flaky forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_hostbased_failed => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_hostbased_passphraseprovider => {
    order => ++$order,
    test_class => [qw(flaky forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_hostbased_openssh_rsa => {
    order => ++$order,
    test_class => [qw(feature_sodium flaky forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_hostbased_rewrite_user => {
    order => ++$order,
    test_class => [qw(flaky forking mod_rewrite mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_kbdint => {
    order => ++$order,
    test_class => [qw(forking mod_auth_otp mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_kbdint_failed => {
    order => ++$order,
    test_class => [qw(forking mod_auth_otp mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_kbdint_rewrite_user => {
    order => ++$order,
    test_class => [qw(forking mod_auth_otp mod_rewrite mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_password => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_password_failed => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_password_with_banner => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_password_twice => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_password_rewrite_user => {
    order => ++$order,
    test_class => [qw(forking mod_rewrite mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_publickey => {
    order => ++$order,
    test_class => [qw(flaky forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_publickey_failed => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_publickey_rewrite_user => {
    order => ++$order,
    test_class => [qw(flaky forking mod_rewrite mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_chain_password_kbdint => {
    order => ++$order,
    test_class => [qw(forking mod_auth_otp mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_auth_chain_publickey_kbdint => {
    order => ++$order,
    test_class => [qw(forking mod_auth_otp mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_verify_server_off => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_verify_server_on => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_sftp_without_auth => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_sftp_stat => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_sftp_upload => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_sftp_download => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_sftp_readdir => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_scp_upload => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_scp_download => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_dh_group1_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  # See: https://github.com/proftpd/proftpd/issues/323
  proxy_reverse_backend_ssh_server_rekey_kex_dh_group1_sha1_zlib_openssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_dh_group14_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_dh_group14_sha256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_dh_group16_sha512 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_dh_group18_sha512 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_dh_gex_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_dh_gex_sha256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_ecdh_sha2_nistp256 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_ecdh_sha2_nistp384 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_ecdh_sha2_nistp521 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_rsa1024_sha1 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_server_rekey_kex_curve25519_sha256 => {
    order => ++$order,
    test_class => [qw(feature_sodium forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_ext_client_rekey => {
    order => ++$order,
    test_class => [qw(flaky forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_sighup => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_extlog => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_connect_policy_per_host => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_connect_policy_per_user => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_connect_policy_per_user_by_json => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

  proxy_reverse_backend_ssh_connect_policy_per_group => {
    order => ++$order,
    test_class => [qw(forking mod_sftp reverse)],
  },

# XXX TODO?
#  proxy_reverse_backend_ssh_sftp_xferlog
#  proxy_reverse_backend_ssh_scp_xferlog
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  Net-SSH2
  #  Net-SSH2-SFTP

  my $required = [qw(
    Net::SSH2
    Net::SSH2::SFTP
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
  my $openssh_rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_openssh_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");
  my $ecdsa256_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_ecdsa256_key");
  my $ecdsa384_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_ecdsa384_key");
  my $ecdsa521_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_ecdsa521_key");
  my $ed25519_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_openssh_ed25519_key");

  my $passphrase_rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/passphrase_host_rsa_key");

  unless (chmod(0400, $rsa_host_key, $openssh_rsa_host_key, $dsa_host_key,
      $ecdsa256_host_key, $ecdsa384_host_key, $ecdsa521_host_key,
      $ed25519_host_key, $passphrase_rsa_host_key)) {
    die("Can't set perms on mod_sftp hostkeys: $!");
  }
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
    ProxyReverseServers => "sftp://127.0.0.1:$vhost_port",
    ProxyRole => 'reverse',
    ProxyTables => $table_dir,

    ProxySFTPVerifyServer => 'off',
  };

  return $config;
}

sub build_db {
  my $cmd = shift;
  my $db_script = shift;
  my $db_file = shift;
  my $check_exit_status = shift;
  $check_exit_status = 0 unless defined($check_exit_status);

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Executing sqlite3: $cmd\n";
  }

  my (@output, $exit_status);
  @output = `$cmd`;
  $exit_status = $?;

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Output: ", join('', @output), "\n";
  }

  if ($check_exit_status) {
    if ($? != 0) {
      croak("'$cmd' failed");
    }
  }

  # Make sure that, if we're running as root, the database file has
  # the permissions/privs set for use by proftpd
  if ($< == 0) {
    unless (chmod(0666, $db_file)) {
      croak("Can't set perms on $db_file to 0666: $!");
    }
  }

  unlink($db_script);
  return 1;
}

sub get_sftp_bin {
  my $sftp = 'sftp';

  # Example:
  # $ export PROXY_TEST_SFTP_BIN=/Users/tj/local/openssh-7.9p1/bin/sftp

  if (defined($ENV{PROXY_TEST_SFTP_BIN})) {
    $sftp = $ENV{PROXY_TEST_SFTP_BIN};
  }

  return $sftp;
}

sub ssh_auth_with_algos {
  my $self = shift;
  my $cipher_algo = shift;
  my $digest_algo = shift;
  my $kex_algo = shift;
  my $proxy_sftp_opts = shift;
  my $ssh_host_key = shift;
  $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key") unless $ssh_host_key;
  my $comp_algo = shift;

  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo if defined($cipher_algo);
  $proxy_config->{ProxySFTPCompression} = $comp_algo if defined($comp_algo);
  $proxy_config->{ProxySFTPDigests} = $digest_algo if defined($digest_algo);
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo if defined($kex_algo);

  # Some options do not (yet?) apply to mod_proxy.
  my $sftp_opts = $proxy_sftp_opts;

  if ($proxy_sftp_opts =~ /AllowInsecureLogin/) {
    $proxy_sftp_opts =~ s/AllowInsecureLogin//ig;
  }

  if ($proxy_sftp_opts =~ /NoHostkeyRotation/) {
    $proxy_sftp_opts =~ s/NoHostkeyRotation//ig;
  }

  if ($proxy_sftp_opts =~ /^\s*$/) {
    $proxy_sftp_opts = undef;
  }

  $proxy_config->{ProxySFTPOptions} = $proxy_sftp_opts if defined($proxy_sftp_opts);

  if ($sftp_opts =~ /^\s*$/) {
    $sftp_opts = undef;
  }

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.cipher:20 proxy.ssh.disconnect:20 proxy.ssh.mac:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $ssh_host_key

    SFTPCiphers $cipher_algo
    SFTPCompression delayed
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo
EOC

    print $fh "SFTPOptions $sftp_opts\n" if defined($sftp_opts);
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
      sleep(2);

      my $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub ssh_rekey_with_algos {
  my $self = shift;
  my $cipher_algo = shift;
  my $digest_algo = shift;
  my $kex_algo = shift;
  my $proxy_sftp_opts = shift;
  my $ssh_host_key = shift;
  $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key") unless $ssh_host_key;
  my $comp_algo = shift;

  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo if defined($cipher_algo);
  $proxy_config->{ProxySFTPCompression} = $comp_algo if defined($comp_algo);
  $proxy_config->{ProxySFTPDigests} = $digest_algo if defined($digest_algo);
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo if defined($kex_algo);

  if ($proxy_sftp_opts =~ /^\s*$/) {
    $proxy_sftp_opts = undef;
  }

  $proxy_config->{ProxySFTPOptions} = $proxy_sftp_opts if defined($proxy_sftp_opts);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    # Make a file that's larger than the maximum SSH2 packet size, forcing
    # the sftp code to loop properly until the entire large file is sent.

    print $fh "ABCDefgh" x 262144;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $test_file2 = File::Spec->rel2abs("$tmpdir/test2.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.cipher:20 proxy.ssh.disconnect:20 proxy.ssh.mac:20 proxy.ssh.packet:20 proxy.ssh.kex:30 proxy.ssh.keys:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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
  TimeoutIdle 10

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $ssh_host_key

    SFTPCiphers $cipher_algo
    SFTPCompression delayed
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo
    SFTPRekey required 5 1 2
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
      my $test_wfh;
      unless (open($test_wfh, "> $test_file2")) {
        die("Can't read $test_file2: $!");
      }

      binmode($test_wfh);

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

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP OPEN request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $test_rfh = $sftp->open('test.dat', O_RDONLY);
      unless ($test_rfh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.dat: [$err_name] ($err_code)");
      }

      my $buf;
      my $bufsz = 8192;

      my $res = $test_rfh->read($buf, $bufsz);
      while ($res) {
        print $test_wfh $buf;

        $res = $test_rfh->read($buf, $bufsz);
      }

      unless (close($test_wfh)) {
        die("Can't write $test_file2: $!");
      }

      # To issue the FXP_CLOSE, we have to explicitly destroy the filehandle
      $test_rfh = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();

      unless (-f $test_file2) {
        die("$test_file2 file does not exist as expected");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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
    # Calculate the MD5 checksum of the uploaded file, for comparison with the
    # file that was uploaded.
    $ctx->reset();
    my $md5;

    if (open(my $fh, "< $test_file2")) {
      binmode($fh);
      $ctx->addfile($fh);
      $md5 = $ctx->hexdigest();
      close($fh);

    } else {
      die("Can't read $test_file2: $!");
    }

    $self->assert($expected_md5 eq $md5,
      test_msg("Expected '$expected_md5', got '$md5'"));
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_connect_bad_version_format {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  # We deliberately do NOT configure mod_sftp in this destination/target
  # backend vhost, in order to force a non-SSH banner for the proxied
  # connection.
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

      if ($ssh2->connect('127.0.0.1', $port)) {
        die("Connected to SSH2 server unexpectedly");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 15) };
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
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /Bad protocol version/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      $self->assert($ok, test_msg("Did not see expected ProxyLog message about bad protocol version"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_connect_timeoutlogin {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $timeout_login = 2;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    TimeoutLogin => $timeout_login,

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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
  TimeoutLogin 15

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
      sleep(2);

      my $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      # Trigger TimeoutLogin by waiting longer than that to authenticate.
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Waiting longer than TimeoutLogin ($timeout_login) secs\n";
      }
      sleep($timeout_login + 1);

      if ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        die("Login succeed to SSH2 server unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /Login timeout exceeded/) {
          $ok = 1;
          last;
        }
      }

      close($fh);

      # Note that this log message is logged at the INFO level, which is only
      # visible here when TEST_VERBOSE is enabled.
      if ($ENV{TEST_VERBOSE}) {
        $self->assert($ok, test_msg("Did not see expected ProxyLog message about TimeoutLogin"));
      }

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_kex_dh_group1_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group1-sha1';
  my $proxy_sftp_opts = 'AllowWeakDH';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_dh_group14_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_dh_group14_sha256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha256';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_dh_group16_sha512 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group16-sha512';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_dh_group18_sha512 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group18-sha512';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_dh_gex_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_dh_gex_sha256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha256';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_ecdh_sha2_nistp256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'ecdh-sha2-nistp256';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_ecdh_sha2_nistp384 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'ecdh-sha2-nistp384';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_ecdh_sha2_nistp521 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'ecdh-sha2-nistp521';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_curve25519_sha256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'curve25519-sha256';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_curve448_sha512 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'curve448-sha512';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_kex_rsa1024_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'rsa1024-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_hostkey_rsa {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';
  my $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # TODO: Technically, we end up using 'rsa-sha2-512', since that is what
  # mod_sftp will offer; the hostkey algorithms are currently not configurable.
  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, $ssh_host_key);
}

sub proxy_reverse_backend_ssh_hostkey_rsa_sha256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';
  my $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # TODO: Technically, we end up using 'rsa-sha2-512', since that is what
  # mod_sftp will offer; the hostkey algorithms are currently not configurable.
  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, $ssh_host_key);
}

sub proxy_reverse_backend_ssh_hostkey_rsa_sha512 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';
  my $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # TODO: Technically, we end up using 'rsa-sha2-512', since that is what
  # mod_sftp will offer; the hostkey algorithms are currently not configurable.
  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, $ssh_host_key);
}

sub proxy_reverse_backend_ssh_hostkey_dss {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';
  my $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, $ssh_host_key);
}

sub proxy_reverse_backend_ssh_hostkey_ecdsa256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';
  my $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_ecdsa256_key");

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, $ssh_host_key);
}

sub proxy_reverse_backend_ssh_hostkey_ecdsa384 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';
  my $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_ecdsa384_key");

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, $ssh_host_key);
}

sub proxy_reverse_backend_ssh_hostkey_ecdsa521 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';
  my $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_ecdsa521_key");

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, $ssh_host_key);
}

sub proxy_reverse_backend_ssh_hostkey_ed25519 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';
  my $ssh_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_openssh_ed25519_key");

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, $ssh_host_key);
}

sub proxy_reverse_backend_ssh_cipher_aes256_gcm {
  my $self = shift;
  my $cipher_algo = 'aes256-gcm@openssh.com';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_aes256_ctr {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_aes256_cbc {
  my $self = shift;
  my $cipher_algo = 'aes256-cbc';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_aes192_ctr {
  my $self = shift;
  my $cipher_algo = 'aes192-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_aes192_cbc {
  my $self = shift;
  my $cipher_algo = 'aes192-cbc';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_aes128_gcm {
  my $self = shift;
  my $cipher_algo = 'aes128-gcm@openssh.com';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_aes128_ctr {
  my $self = shift;
  my $cipher_algo = 'aes128-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_aes128_cbc {
  my $self = shift;
  my $cipher_algo = 'aes128-cbc';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_blowfish_ctr {
  my $self = shift;
  my $cipher_algo = 'blowfish-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_blowfish_cbc {
  my $self = shift;
  my $cipher_algo = 'blowfish-cbc';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_cast128_cbc {
  my $self = shift;
  my $cipher_algo = 'cast128-cbc';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_arcfour256 {
  my $self = shift;
  my $cipher_algo = 'arcfour256';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_arcfour128 {
  my $self = shift;
  my $cipher_algo = 'arcfour128';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_3des_ctr {
  my $self = shift;
  my $cipher_algo = '3des-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_3des_cbc {
  my $self = shift;
  my $cipher_algo = '3des-cbc';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_cipher_none {
  my $self = shift;

  # Note that in order to use the 'none' algorithms for _e.g. password
  # authentication, mod_sftp requires the AllowInsecureLogin option.
  my $cipher_algo = 'none';

  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = 'AllowInsecureLogin';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_sha1_etm_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1-etm@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_sha1_96 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1-96';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_sha1_96_etm_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1-96-etm@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_md5 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-md5';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_md5_etm_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-md5-etm@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_md5_96 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-md5-96';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_md5_96_etm_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-md5-96-etm@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_ripemd160 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-ripemd160';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_sha256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha2-256';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_sha256_etm_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha2-256-etm@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_sha512 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha2-512';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_hmac_sha512_etm_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha2-512-etm@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_umac64_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'umac-64@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_umac64_etm_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'umac-64-etm@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_umac128_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'umac-128@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_umac128_etm_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'umac-128@openssh.com';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_mac_none {
  my $self = shift;

  my $cipher_algo = 'aes256-ctr';

  # Note that in order to use the 'none' algorithms for _e.g. password
  # authentication, mod_sftp requires the AllowInsecureLogin option.
  my $digest_algo = 'none';

  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = 'AllowInsecureLogin';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_compress_none {
  my $self = shift;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $comp_algo = 'off';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, undef, $comp_algo);
}

sub proxy_reverse_backend_ssh_compress_zlib {
  my $self = shift;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $comp_algo = 'on';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, undef, $comp_algo);
}

sub proxy_reverse_backend_ssh_compress_zlib_openssh {
  my $self = shift;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $comp_algo = 'delayed';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_auth_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, undef, $comp_algo);
}

sub proxy_reverse_backend_ssh_auth_none {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

      my $auth_methods = $ssh2->auth_list($setup->{user});
      unless ($auth_methods) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't list SSH2 server auth methods: [$err_name] ($err_code) $err_str");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# authentication methods: $auth_methods\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_hostbased {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For hostbased authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      my $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_hostbased($setup->{user}, $rsa_pub_key, $rsa_priv_key,
          '127.0.0.1', $setup->{user})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_hostbased_failed {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For hostbased authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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

      # We expect this to fail because we have not configured any
      # ProxySFTPHostKeys.
      if ($ssh2->auth_hostbased($setup->{user}, $rsa_pub_key, $rsa_priv_key,
          '127.0.0.1', $setup->{user})) {
        die("Hostbased login succeeded unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_hostbased_passphraseprovider {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For hostbased authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");

  my $passphrase_rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/passphrase_host_rsa_key");
  my $passphrase_provider = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/sftp-get-passphrase.pl");

  $proxy_config->{ProxySFTPHostKey} = $passphrase_rsa_host_key;
  $proxy_config->{ProxySFTPPassPhraseProvider} = $passphrase_provider;

  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_passphrase_rsa_keys");
  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      my $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_hostbased($setup->{user}, $rsa_pub_key, $rsa_priv_key,
          '127.0.0.1', $setup->{user})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_hostbased_openssh_rsa {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For hostbased authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");

  my $openssh_rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_openssh_rsa_key");
  $proxy_config->{ProxySFTPHostKey} = $openssh_rsa_host_key;

  # This "authorized_passphrase_rsa_keys" file contains the RFC4716 public
  # key for this OpenSSH-encoded private key, too.
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_passphrase_rsa_keys");
  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      my $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_hostbased($setup->{user}, $rsa_pub_key, $rsa_priv_key,
          '127.0.0.1', $setup->{user})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_hostbased_rewrite_user {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For hostbased authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_rewrite.c' => [
        'RewriteEngine on',
        "RewriteLog $setup->{log_file}",

        'RewriteMap lowercase int:tolower',
        'RewriteCondition %m USER',
        'RewriteRule ^(.*)$ ${lowercase:$1}',
      ],

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      my $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_hostbased(uc($setup->{user}), $rsa_pub_key,
          $rsa_priv_key, '127.0.0.1', $setup->{user})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_publickey {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For publickey authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");

  # For hostbased authentication
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      my $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_publickey_failed {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For publickey authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");

  # For hostbased authentication
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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

      if ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        die("Publickey authentication succeeded unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_publickey_rewrite_user {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For publickey authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");

  # For hostbased authentication
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_rewrite.c' => [
        'RewriteEngine on',
        "RewriteLog $setup->{log_file}",

        'RewriteMap lowercase int:tolower',
        'RewriteCondition %m USER',
        'RewriteRule ^(.*)$ ${lowercase:$1}',
      ],

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      my $ssh2 = Net::SSH2->new();

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey(uc($setup->{user}), $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_password {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_password_failed {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

      if ($ssh2->auth_password($setup->{user}, 'BadPassword')) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Successfully authenticated to SSH2 server unexpectedly");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_password_with_banner {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $banner_file = File::Spec->rel2abs("$tmpdir/banner.txt");
  if (open(my $fh, "> $banner_file")) {
    print $fh <<EOB;
-----BEGIN BANNER-----
Hello, SFTP client!  Thank you for using our service.
All Rights Reserved.
-----END BANNER-----
EOB
    unless (close($fh)) {
      die("Can't write $banner_file: $!");
    }

  } else {
    die("Can't open $banner_file: $!");
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

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPDisplayBanner $banner_file
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

      if ($ssh2->auth_password($setup->{user}, 'BadPassword')) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Successfully authenticated to SSH2 server unexpectedly");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_password_twice {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

      # Now, authenticate again, to make sure mod_proxy handles this case
      # properly.
      #
      # Since mod_proxy should be ignoring this additional USERAUTH_REQUEST,
      # we need to time out the libssh2 request before the testcase times out.

      my $auth_timed_out = 0;

      eval {
        local %SIG;
        $SIG{ALRM} = sub { $auth_timed_out = 1; };

        alarm(1);
        if ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
          alarm(0);
          die("Second login succeeded unexpectedly");
        }

        # Clear the pending alarm
        alarm(0);
      };

      $self->assert($auth_timed_out,
        test_msg("Expected timeout out auth request"));

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_password_rewrite_user {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_rewrite.c' => [
        'RewriteEngine on',
        "RewriteLog $setup->{log_file}",

        'RewriteMap lowercase int:tolower',
        'RewriteCondition %m USER',
        'RewriteRule ^(.*)$ ${lowercase:$1}',
      ],

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

      unless ($ssh2->auth_password(uc($setup->{user}), $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_kbdint {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For keyboard-interactive authentication (via OTP)
  my $db_file = File::Spec->rel2abs("$tmpdir/auth_otp.db");

  # Build up sqlite3 command to create HOTP tables
  my $db_script = File::Spec->rel2abs("$tmpdir/hotp.sql");

  # mod_auth_otp wants this secret to be base32-encoded, for interoperability
  # with Google Authenticator.
  require MIME::Base32;

  my $secret = 'Sup3rS3Cr3t';
  my $base32_secret = MIME::Base32::encode_base32($secret);
  my $counter = 777;
  my $bad_secret = 'B@d1YK3pts3kr3T!';

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE auth_otp (
  user TEXT PRIMARY KEY,
  secret TEXT,
  counter INTEGER
);
INSERT INTO auth_otp (user, secret, counter) VALUES ('$setup->{user}', '$base32_secret', $counter);

EOS

    unless (close($fh)) {
      die("Can't write $db_script: $!");
    }

  } else {
    die("Can't open $db_script: $!");
  }

  my $cmd = "sqlite3 $db_file < $db_script";
  build_db($cmd, $db_script, $db_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:20 auth_otp:20 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 sql:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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
  AuthOrder mod_auth_otp.c mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_auth_otp.c>
    AuthOTPEngine on
    AuthOTPLog $setup->{log_file}
    AuthOTPAlgorithm hotp

    # Assumes default table names, column names
    AuthOTPTable sql:/get-user-hotp/update-user-hotp
  </IfModule>

  <IfModule mod_delay.c>
    DelayEngine off
  </IfModule>

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    # Configure mod_sftp to only use the keyboard-interactive method.
    # NOTE: How to handle this when both mod_auth_otp AND mod_sftp_pam
    # are used/loaded?
    SFTPAuthMethods keyboard-interactive
  </IfModule>

  <IfModule mod_sql.c>
    SQLEngine log
    SQLBackend sqlite3
    SQLConnectInfo $db_file
    SQLLogFile $setup->{log_file}

    SQLNamedQuery get-user-hotp SELECT "secret, counter FROM auth_otp WHERE user = '%{0}'"
    SQLNamedQuery update-user-hotp UPDATE "counter = %{1} WHERE user = '%{0}'" auth_otp
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

  require Authen::OATH;
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

      # Calculate HOTP
      my $oath = Authen::OATH->new();
      my $hotp = $oath->hotp($secret, $counter);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Generated HOTP $hotp for counter ", $counter, "\n";
      }

      unless ($ssh2->auth_keyboard($setup->{user}, $hotp)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_kbdint_failed {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:20 auth_otp:20 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 sql:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_auth_otp.c>
    AuthOTPEngine on
    AuthOTPLog $setup->{log_file}
    AuthOTPAlgorithm hotp

    # Assumes default table names, column names
    AuthOTPTable sql:/get-user-hotp/update-user-hotp
  </IfModule>

  <IfModule mod_delay.c>
    DelayEngine off
  </IfModule>

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    # Configure mod_sftp to only use the keyboard-interactive method.
    # NOTE: How to handle this when both mod_auth_otp AND mod_sftp_pam
    # are used/loaded?
    SFTPAuthMethods keyboard-interactive
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

  require Authen::OATH;
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

      # Calculate HOTP
      my $oath = Authen::OATH->new();

      my $counter = 1;
      my $hotp = $oath->hotp('foobar', $counter);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Generated HOTP $hotp for counter ", $counter, "\n";
      }

      if ($ssh2->auth_keyboard($setup->{user}, $hotp)) {
        die("keyboard-interactive login succeeded unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_kbdint_rewrite_user {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For keyboard-interactive authentication (via OTP)
  my $db_file = File::Spec->rel2abs("$tmpdir/auth_otp.db");

  # Build up sqlite3 command to create HOTP tables
  my $db_script = File::Spec->rel2abs("$tmpdir/hotp.sql");

  # mod_auth_otp wants this secret to be base32-encoded, for interoperability
  # with Google Authenticator.
  require MIME::Base32;

  my $secret = 'Sup3rS3Cr3t';
  my $base32_secret = MIME::Base32::encode_base32($secret);
  my $counter = 777;
  my $bad_secret = 'B@d1YK3pts3kr3T!';

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE auth_otp (
  user TEXT PRIMARY KEY,
  secret TEXT,
  counter INTEGER
);
INSERT INTO auth_otp (user, secret, counter) VALUES ('$setup->{user}', '$base32_secret', $counter);

EOS

    unless (close($fh)) {
      die("Can't write $db_script: $!");
    }

  } else {
    die("Can't open $db_script: $!");
  }

  my $cmd = "sqlite3 $db_file < $db_script";
  build_db($cmd, $db_script, $db_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:20 auth_otp:20 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 sql:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_rewrite.c' => [
        'RewriteEngine on',
        "RewriteLog $setup->{log_file}",

        'RewriteMap lowercase int:tolower',
        'RewriteCondition %m USER',
        'RewriteRule ^(.*)$ ${lowercase:$1}',
      ],

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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
  AuthOrder mod_auth_otp.c mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_auth_otp.c>
    AuthOTPEngine on
    AuthOTPLog $setup->{log_file}
    AuthOTPAlgorithm hotp

    # Assumes default table names, column names
    AuthOTPTable sql:/get-user-hotp/update-user-hotp
  </IfModule>

  <IfModule mod_delay.c>
    DelayEngine off
  </IfModule>

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    # Configure mod_sftp to only use the keyboard-interactive method.
    # NOTE: How to handle this when both mod_auth_otp AND mod_sftp_pam
    # are used/loaded?
    SFTPAuthMethods keyboard-interactive
  </IfModule>

  <IfModule mod_sql.c>
    SQLEngine log
    SQLBackend sqlite3
    SQLConnectInfo $db_file
    SQLLogFile $setup->{log_file}

    SQLNamedQuery get-user-hotp SELECT "secret, counter FROM auth_otp WHERE user = '%{0}'"
    SQLNamedQuery update-user-hotp UPDATE "counter = %{1} WHERE user = '%{0}'" auth_otp
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

  require Authen::OATH;
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

      # Calculate HOTP
      my $oath = Authen::OATH->new();
      my $hotp = $oath->hotp($secret, $counter);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Generated HOTP $hotp for counter ", $counter, "\n";
      }

      unless ($ssh2->auth_keyboard(uc($setup->{user}), $hotp)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_chain_password_kbdint {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For keyboard-interactive authentication (via OTP)
  my $db_file = File::Spec->rel2abs("$tmpdir/auth_otp.db");

  # Build up sqlite3 command to create HOTP tables
  my $db_script = File::Spec->rel2abs("$tmpdir/hotp.sql");

  # mod_auth_otp wants this secret to be base32-encoded, for interoperability
  # with Google Authenticator.
  require MIME::Base32;

  my $secret = 'Sup3rS3Cr3t';
  my $base32_secret = MIME::Base32::encode_base32($secret);
  my $counter = 777;
  my $bad_secret = 'B@d1YK3pts3kr3T!';

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE auth_otp (
  user TEXT PRIMARY KEY,
  secret TEXT,
  counter INTEGER
);
INSERT INTO auth_otp (user, secret, counter) VALUES ('$setup->{user}', '$base32_secret', $counter);

EOS

    unless (close($fh)) {
      die("Can't write $db_script: $!");
    }

  } else {
    die("Can't open $db_script: $!");
  }

  my $cmd = "sqlite3 $db_file < $db_script";
  build_db($cmd, $db_script, $db_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:20 auth_otp:20 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 sql:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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
  AuthOrder mod_auth_otp.c mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_auth_otp.c>
    AuthOTPEngine on
    AuthOTPLog $setup->{log_file}
    AuthOTPAlgorithm hotp

    # Assumes default table names, column names
    AuthOTPTable sql:/get-user-hotp/update-user-hotp
  </IfModule>

  <IfModule mod_delay.c>
    DelayEngine off
  </IfModule>

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    # Configure mod_sftp to require both password and keyboard-interactive
    # methods.
    SFTPAuthMethods password+keyboard-interactive
  </IfModule>

  <IfModule mod_sql.c>
    SQLEngine log
    SQLBackend sqlite3
    SQLConnectInfo $db_file
    SQLLogFile $setup->{log_file}

    SQLNamedQuery get-user-hotp SELECT "secret, counter FROM auth_otp WHERE user = '%{0}'"
    SQLNamedQuery update-user-hotp UPDATE "counter = %{1} WHERE user = '%{0}'" auth_otp
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

  require Authen::OATH;
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

      if ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        die("Login succeeded unexpectedly with just password authentication");
      }

      # Calculate HOTP
      my $oath = Authen::OATH->new();
      my $hotp = $oath->hotp($secret, $counter);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Generated HOTP $hotp for counter ", $counter, "\n";
      }

      unless ($ssh2->auth_keyboard($setup->{user}, $hotp)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_auth_chain_publickey_kbdint {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For publickey authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");

  # For hostbased authentication
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  # For keyboard-interactive authentication (via OTP)
  my $db_file = File::Spec->rel2abs("$tmpdir/auth_otp.db");

  # Build up sqlite3 command to create HOTP tables
  my $db_script = File::Spec->rel2abs("$tmpdir/hotp.sql");

  # mod_auth_otp wants this secret to be base32-encoded, for interoperability
  # with Google Authenticator.
  require MIME::Base32;

  my $secret = 'Sup3rS3Cr3t';
  my $base32_secret = MIME::Base32::encode_base32($secret);
  my $counter = 777;
  my $bad_secret = 'B@d1YK3pts3kr3T!';

  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE auth_otp (
  user TEXT PRIMARY KEY,
  secret TEXT,
  counter INTEGER
);
INSERT INTO auth_otp (user, secret, counter) VALUES ('$setup->{user}', '$base32_secret', $counter);

EOS

    unless (close($fh)) {
      die("Can't write $db_script: $!");
    }

  } else {
    die("Can't open $db_script: $!");
  }

  my $cmd = "sqlite3 $db_file < $db_script";
  build_db($cmd, $db_script, $db_file);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:20 auth_otp:20 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 sql:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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
  AuthOrder mod_auth_otp.c mod_auth_file.c

  AllowOverride off
  WtmpLog off
  TransferLog none

  <IfModule mod_auth_otp.c>
    AuthOTPEngine on
    AuthOTPLog $setup->{log_file}
    AuthOTPAlgorithm hotp

    # Assumes default table names, column names
    AuthOTPTable sql:/get-user-hotp/update-user-hotp
  </IfModule>

  <IfModule mod_delay.c>
    DelayEngine off
  </IfModule>

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys

    # Configure mod_sftp to require both hostbased and keyboard-interactive
    # methods.
    SFTPAuthMethods hostbased+keyboard-interactive
  </IfModule>

  <IfModule mod_sql.c>
    SQLEngine log
    SQLBackend sqlite3
    SQLConnectInfo $db_file
    SQLLogFile $setup->{log_file}

    SQLNamedQuery get-user-hotp SELECT "secret, counter FROM auth_otp WHERE user = '%{0}'"
    SQLNamedQuery update-user-hotp UPDATE "counter = %{1} WHERE user = '%{0}'" auth_otp
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

  require Authen::OATH;
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

      if ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        die("Login succeeded unexpectedly with just publickey authentication");
      }

      # Calculate HOTP
      my $oath = Authen::OATH->new();
      my $hotp = $oath->hotp($secret, $counter);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Generated HOTP $hotp for counter ", $counter, "\n";
      }

      unless ($ssh2->auth_keyboard($setup->{user}, $hotp)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_verify_server_off {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxySFTPVerifyServer} = 'off';

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.db:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.db:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_verify_server_on {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxySFTPVerifyServer} = 'on';

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # We force a hostkey mismatch by manually creating the expected 'proxy-ssh.db'
  # SQLite database, populated with a hostkey entry that will not match.
  #
  # NOTE: Try to keep the schema_version here in sync with the code!

  my $table_dir = $proxy_config->{ProxyTables};
  mkpath($table_dir);

  my $db_file = File::Spec->rel2abs("$table_dir/proxy-ssh.db");

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Fiddling with SQLite database file $db_file\n";
  }

  my $db_script = File::Spec->rel2abs("$tmpdir/proxy-ssh.sql");
  if (open(my $fh, "> $db_script")) {
    print $fh <<EOS;
CREATE TABLE schema_version (
  schema TEXT NOT NULL PRIMARY KEY,
  version INTEGER NOT NULL
);
INSERT INTO schema_version (schema, version) VALUES ('proxy_ssh', 7);

CREATE TABLE proxy_ssh_hostkeys (
  backend_uri STRING NOT NULL PRIMARY KEY,
  vhost_id INTEGER NOT NULL,
  algo TEXT NOT NULL,
  hostkey BLOB NOT NULL
);
INSERT INTO proxy_ssh_hostkeys (vhost_id, backend_uri, algo, hostkey) VALUES (1, '$proxy_config->{ProxyReverseServers}', 'ssh-ed25519', X'4E6F74415265616C4B6579');
EOS
    unless (close($fh)) {
      die("Can't write $db_script: $!");
    }

  } else {
    die("Can't open $db_script: $!");
  }

  my $cmd = "sqlite3 -batch -echo $db_file < $db_script";
  build_db($cmd, $db_script, $db_file);
  unlink($db_script);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.db:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.db:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_sftp_without_auth {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key
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

      my $sftp = $ssh2->sftp();
      if ($sftp) {
        die("Started SFTP channel unexpectedly");
      }

      my ($err_code, $err_name, $err_str) = $ssh2->error();

      my $expected;

      # The expected error messages depend on the version of libssh2 being
      # used.
      $self->assert($err_name eq 'LIBSSH2_ERROR_INVAL' or
                    $err_name eq 'LIBSSH2_ERROR_CHANNEL_FAILURE',
        test_msg("Expected 'LIBSSH2_ERROR_INVAL' or 'LIBSSH2_ERROR_CHANNEL_FAILURE', got '$err_name'"));

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_sftp_stat {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key
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

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_sftp_upload {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    # Make a file that's larger than the maximum SSH2 packet size, forcing
    # the sftp code to loop properly until the entire large file is sent.

    print $fh "ABCDefgh" x 16384;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $test_file2 = File::Spec->rel2abs("$tmpdir/test2.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key
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
      my $test_rfh;
      unless (open($test_rfh, "< $test_file")) {
        die("Can't read $test_file: $!");
      }

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

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP OPEN request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $test_wfh = $sftp->open('test2.dat', O_WRONLY|O_CREAT|O_TRUNC, 0644);
      unless ($test_wfh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.dat: [$err_name] ($err_code)");
      }

      my $buf;
      my $bufsz = 8192;

      while (read($test_rfh, $buf, $bufsz)) {
        print $test_wfh $buf;
      }

      close($test_rfh);

      # To issue the FXP_CLOSE, we have to explicitly destroy the filehandle
      $test_wfh = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();

      unless (-f $test_file2) {
        die("$test_file2 file does not exist as expected");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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
    # Calculate the MD5 checksum of the uploaded file, for comparison with the
    # file that was uploaded.
    $ctx->reset();
    my $md5;

    if (open(my $fh, "< $test_file2")) {
      binmode($fh);
      $ctx->addfile($fh);
      $md5 = $ctx->hexdigest();
      close($fh);

    } else {
      die("Can't read $test_file2: $!");
    }

    $self->assert($expected_md5 eq $md5,
      test_msg("Expected '$expected_md5', got '$md5'"));
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_sftp_download {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    # Make a file that's larger than the maximum SSH2 packet size, forcing
    # the sftp code to loop properly until the entire large file is sent.

    print $fh "ABCDefgh" x 16384;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $test_file2 = File::Spec->rel2abs("$tmpdir/test2.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key
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
      my $test_wfh;
      unless (open($test_wfh, "> $test_file2")) {
        die("Can't read $test_file2: $!");
      }

      binmode($test_wfh);

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

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP OPEN request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $test_rfh = $sftp->open('test.dat', O_RDONLY);
      unless ($test_rfh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.dat: [$err_name] ($err_code)");
      }

      my $buf;
      my $bufsz = 8192;

      my $res = $test_rfh->read($buf, $bufsz);
      while ($res) {
        print $test_wfh $buf;

        $res = $test_rfh->read($buf, $bufsz);
      }

      unless (close($test_wfh)) {
        die("Can't write $test_file2: $!");
      }

      # To issue the FXP_CLOSE, we have to explicitly destroy the filehandle
      $test_rfh = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();

      unless (-f $test_file2) {
        die("$test_file2 file does not exist as expected");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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
    # Calculate the MD5 checksum of the uploaded file, for comparison with the
    # file that was uploaded.
    $ctx->reset();
    my $md5;

    if (open(my $fh, "< $test_file2")) {
      binmode($fh);
      $ctx->addfile($fh);
      $md5 = $ctx->hexdigest();
      close($fh);

    } else {
      die("Can't read $test_file2: $!");
    }

    $self->assert($expected_md5 eq $md5,
      test_msg("Expected '$expected_md5', got '$md5'"));
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_sftp_readdir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key
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

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP OPENDIR request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $dirh = $sftp->opendir('.');
      unless ($dirh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open directory '.': [$err_name] ($err_code)");
      }

      my $res = {};

      my $file = $dirh->read();
      while ($file) {
        $res->{$file->{name}} = $file;
        $file = $dirh->read();
      }

      # To issue the FXP_CLOSE, we have to explicitly destroy the dirhandle
      $dirh = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();

      my $expected = {
        '.' => 1,
        '..' => 1,
        'proxy.conf' => 1,
        'proxy.group' => 1,
        'proxy.passwd' => 1,
        'proxy.pid' => 1,
        'proxy.scoreboard' => 1,
        'proxy.scoreboard.lck' => 1,
        'var' => 1,
      };

      my $ok = 1;
      my $mismatch;

      my $seen = [];
      foreach my $name (keys(%$res)) {
        push(@$seen, $name);

        unless (defined($expected->{$name})) {
          $mismatch = $name;
          $ok = 0;
          last;
        }
      }

      unless ($ok) {
        die("Unexpected name '$mismatch' appeared in READDIR data")
      }

      # Now remove from $expected all of the paths we saw; if there are
      # any entries remaining in $expected, something went wrong.
      foreach my $name (@$seen) {
        delete($expected->{$name});
      }

      my $remaining = scalar(keys(%$expected));
      $self->assert(0 == $remaining,
        test_msg("Expected 0, got $remaining"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_scp_upload {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    # Make a file that's larger than the maximum SSH2 packet size, forcing
    # the sftp code to loop properly until the entire large file is sent.

    print $fh "ABCDefgh" x 16384;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $test_file2 = File::Spec->rel2abs("$tmpdir/test2.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20 scp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key
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

      my $res = $ssh2->scp_put($test_file, 'test2.dat');
      unless ($res) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't upload 'test.dat' to server: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();

      unless (-f $test_file2) {
        die("$test_file2 file does not exist as expected");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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
    # Calculate the MD5 checksum of the uploaded file, for comparison with the
    # file that was uploaded.
    $ctx->reset();
    my $md5;

    if (open(my $fh, "< $test_file2")) {
      binmode($fh);
      $ctx->addfile($fh);
      $md5 = $ctx->hexdigest();
      close($fh);

    } else {
      die("Can't read $test_file2: $!");
    }

    $self->assert($expected_md5 eq $md5,
      test_msg("Expected '$expected_md5', got '$md5'"));
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_scp_download {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    # Make a file that's larger than the maximum SSH2 packet size, forcing
    # the sftp code to loop properly until the entire large file is sent.

    print $fh "ABCDefgh" x 16384;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the
  # downloaded file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $test_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $test_file: $!");
  }

  my $test_file2 = File::Spec->rel2abs("$tmpdir/test2.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'response:25 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20 scp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key
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

      my $res = $ssh2->scp_get('test.dat', $test_file2);
      unless ($res) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't download 'test.dat' from server: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();

      unless (-f $test_file2) {
        die("$test_file2 file does not exist as expected");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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
    # Calculate the MD5 checksum of the uploaded file, for comparison with the
    # file that was uploaded.
    $ctx->reset();
    my $md5;

    if (open(my $fh, "< $test_file2")) {
      binmode($fh);
      $ctx->addfile($fh);
      $md5 = $ctx->hexdigest();
      close($fh);

    } else {
      die("Can't read $test_file2: $!");
    }

    $self->assert($expected_md5 eq $md5,
      test_msg("Expected '$expected_md5', got '$md5'"));
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_dh_group1_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group1-sha1';
  my $proxy_sftp_opts = 'AllowWeakDH';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_dh_group1_sha1_zlib_openssh {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $comp_algo = 'delayed';
  my $kex_algo = 'diffie-hellman-group1-sha1';
  my $proxy_sftp_opts = 'AllowWeakDH';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts, undef, $comp_algo);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_dh_group14_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_dh_group14_sha256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha256';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_dh_group16_sha512 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group16-sha512';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_dh_group18_sha512 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group18-sha512';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_dh_gex_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha1';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_dh_gex_sha256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group-exchange-sha256';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_ecdh_sha2_nistp256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'ecdh-sha2-nistp256';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_ecdh_sha2_nistp384 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'ecdh-sha2-nistp384';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_ecdh_sha2_nistp521 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'ecdh-sha2-nistp521';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_rsa1024_sha1 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'rsa1024-sha1';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_server_rekey_kex_curve25519_sha256 {
  my $self = shift;
  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'curve25519-sha256';
  my $proxy_sftp_opts = '';

  ssh_rekey_with_algos($self, $cipher_algo, $digest_algo, $kex_algo,
    $proxy_sftp_opts);
}

sub proxy_reverse_backend_ssh_ext_client_rekey {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For publickey authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");

  # For hostbased authentication
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  my $src_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $src_file")) {
    # Make a file that's larger than the maximum SSH2 packet size, forcing
    # the sftp code to loop properly until the entire large file is sent.

    print $fh "ABCDefgh" x 262144;
    unless (close($fh)) {
      die("Can't write $src_file: $!");
    }

    # Make sure that, if we're running as root, that the test file has
    # permissions/privs set for the account we create
    if ($< == 0) {
      unless (chown($setup->{uid}, $setup->{gid}, $src_file)) {
        die("Can't set owner of $src_file to $setup->{uid}/$setup->{gid}: $!");
      }
    }

  } else {
    die("Can't open $src_file: $!");
  }

  # Calculate the MD5 checksum of this file, for comparison with the downloaded
  # file.
  my $ctx = Digest::MD5->new();
  my $expected_md5;

  if (open(my $fh, "< $src_file")) {
    binmode($fh);
    $ctx->addfile($fh);
    $expected_md5 = $ctx->hexdigest();
    close($fh);

  } else {
    die("Can't read $src_file: $!");
  }

  my $dst_file = File::Spec->rel2abs("$tmpdir/test2.dat");

  my $batch_file = File::Spec->rel2abs("$tmpdir/sftp-batch.txt");
  if (open(my $fh, "> $batch_file")) {
    print $fh "get -P $src_file $dst_file\n";

    unless (close($fh)) {
      die("Can't write $batch_file: $!");
    }

  } else {
    die("Can't open $batch_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo

    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      my $sftp = get_sftp_bin();

      my @cmd = (
        $sftp,
        '-oBatchMode=yes',
        '-oCheckHostIP=no',
        '-oRekeyLimit=1M',
        "-oPort=$port",
        "-oIdentityFile=$rsa_priv_key",
        '-oPubkeyAuthentication=yes',
        '-oStrictHostKeyChecking=no',
        '-oUserKnownHostsFile=/dev/null',
        '-vvv',
        '-b',
        "$batch_file",
        "$setup->{user}\@127.0.0.1",
      );

      my $sftp_rh = IO::Handle->new();
      my $sftp_wh = IO::Handle->new();
      my $sftp_eh = IO::Handle->new();

      $sftp_wh->autoflush(1);

      local $SIG{CHLD} = 'DEFAULT';

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Executing: ", join(' ', @cmd), "\n";
      }

      my $sftp_pid = open3($sftp_wh, $sftp_rh, $sftp_eh, @cmd);
      waitpid($sftp_pid, 0);
      my $exit_status = $?;

      # Restore the perms on the priv key
      unless (chmod(0644, $rsa_priv_key)) {
        die("Can't set perms on $rsa_priv_key to 0644: $!");
      }

      my $res;
      my $errstr = '';
      if ($exit_status >> 8 == 0) {
        $errstr = join('', <$sftp_eh>);
        $res = 0;

      } else {
        if ($ENV{TEST_VERBOSE}) {
          $errstr = join('', <$sftp_eh>);
          print STDERR "Stderr: $errstr\n";
        }

        $res = 1;
      }

      unless ($res == 0) {
        die("Can't download $src_file from server: $errstr");
      }

      unless (-f $dst_file) {
        die("File '$dst_file' does not exist as expected");
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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
    $ctx->reset();
    my $md5;

    if (open(my $fh, "< $dst_file")) {
      binmode($fh);
      $ctx->addfile($fh);
      $md5 = $ctx->hexdigest();
      close($fh);

    } else {
      die("Can't read $dst_file: $!");
    }

    $self->assert($expected_md5 eq $md5,
      test_msg("Expected MD5 '$expected_md5', got '$md5'"));
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_sighup {
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
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  # First, start the server.
  server_start($setup->{config_file});

  # Give it a second to start up, then send the SIGHUP signal
  sleep(2);
  server_restart($setup->{pid_file});

  # Give it another second to start up again
  sleep(2);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

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

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $path = 'proxy.conf';
      unless ($sftp->stat($path, 1)) {
        my ($err_code, $err_name) = $sftp->error();
        die("STAT $path failed: [$err_name] ($err_code)");
      }

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_extlog {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $extlog_file = File::Spec->rel2abs("$tmpdir/ext.log");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    LogFormat => 'fmt "%m %J"',
    ExtendedLog => "$extlog_file ALL fmt",

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key
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

      my $sftp_start_ts = [gettimeofday()];
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Opening SFTP channel...\n";
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp_start_elapsed = tv_interval($sftp_start_ts);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Sending SFTP OPENDIR request ($sftp_start_elapsed since SFTP channel opened)...\n";
      }

      my $dirh = $sftp->opendir('.');
      unless ($dirh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open directory '.': [$err_name] ($err_code)");
      }

      my $res = {};

      my $file = $dirh->read();
      while ($file) {
        $res->{$file->{name}} = $file;
        $file = $dirh->read();
      }

      # To issue the FXP_CLOSE, we have to explicitly destroy the dirhandle
      $dirh = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Closing SFTP channel...\n";
      }

      # To close the SFTP channel, we have to explicitly destroy the object
      $sftp = undef;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Disconnecting SSH...\n";
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  if ($ex) {
    test_cleanup($setup->{log_file}, $ex);
    die($ex);
  }

  eval {
    if (open(my $fh, "< $extlog_file")) {
      my $saw_kexinit = 0;
      my $saw_newkeys = 0;
      my $saw_service_request = 0;
      my $saw_service_accept = 0;
      my $saw_userauth_request = 0;
      my $saw_userauth_success = 0;
      my $saw_user = 0;
      my $saw_pass = 0;
      my $saw_channel_success = 0;
      my $saw_channel_data = 0;
      my $saw_channel_eof = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /^KEXINIT/) {
          $saw_kexinit = 1;
          next;
        }

        if ($line =~ /^NEWKEYS/) {
          $saw_newkeys = 1;
          next;
        }

        if ($line =~ /^SERVICE_REQUEST/) {
          $saw_service_request = 1;
          next;
        }

        if ($line =~ /^SERVICE_ACCEPT/) {
          $saw_service_accept = 1;
          next;
        }

        if ($line =~ /^USERAUTH_REQUEST/) {
          $saw_userauth_request = 1;
          next;
        }

        if ($line =~ /^USERAUTH_SUCCESS/) {
          $saw_userauth_success = 1;
          next;
        }

        if ($line =~ /^USER/) {
          $saw_user = 1;
          next;
        }

        if ($line =~ /^PASS/) {
          $saw_pass = 1;
          next;
        }

        if ($line =~ /^CHANNEL_SUCCESS/) {
          $saw_channel_success = 1;
          next;
        }

        if ($line =~ /^CHANNEL_DATA/) {
          $saw_channel_data = 1;
          next;
        }

        if ($line =~ /^CHANNEL_EOF/) {
          $saw_channel_eof = 1;
          last;
        }
      }

      close($fh);

      $self->assert($saw_kexinit,
        test_msg("Did not see expected ExtendedLog KEXINIT message"));
      $self->assert($saw_newkeys,
        test_msg("Did not see expected ExtendedLog NEWKEYS message"));
      $self->assert($saw_userauth_request,
        test_msg("Did not see expected ExtendedLog USERAUTH_REQUEST message"));
      $self->assert($saw_userauth_success,
        test_msg("Did not see expected ExtendedLog USERAUTH_SUCCESS message"));
      $self->assert($saw_user,
        test_msg("Did not see expected ExtendedLog USER message"));
      $self->assert($saw_pass,
        test_msg("Did not see expected ExtendedLog PASS message"));
      $self->assert($saw_channel_success,
        test_msg("Did not see expected ExtendedLog CHANNEL_SUCCESS message"));
      $self->assert($saw_channel_data,
        test_msg("Did not see expected ExtendedLog CHANNEL_DATA message"));
      $self->assert($saw_channel_eof,
        test_msg("Did not see expected ExtendedLog CHANNEL_EOF message"));

    } else {
      die("Can't read $extlog_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub proxy_reverse_backend_ssh_connect_policy_per_host {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerHost';
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxyReverseServers} = "sftp://127.0.0.1:$vhost_port sftp://127.0.0.1:$vhost_port2",

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo
  </IfModule>
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Server"

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
      sleep(2);

      for (my $i = 0; $i < 3; $i++) {
        my $ssh2 = Net::SSH2->new();

        unless ($ssh2->connect('127.0.0.1', $port)) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
        }

        unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
        }

        my $sftp_start_ts = [gettimeofday()];
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Opening SFTP channel...\n";
        }

        my $sftp = $ssh2->sftp();
        unless ($sftp) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
        }

        my $sftp_start_elapsed = tv_interval($sftp_start_ts);
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
        }

        my $path = 'proxy.conf';
        unless ($sftp->stat($path, 1)) {
          my ($err_code, $err_name) = $sftp->error();
          die("STAT $path failed: [$err_name] ($err_code)");
        }

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Closing SFTP channel...\n";
        }

        # To close the SFTP channel, we have to explicitly destroy the object
        $sftp = undef;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Disconnecting SSH...\n";
        }

        $ssh2->disconnect();
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_connect_policy_per_user {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerUser';
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxyReverseServers} = "sftp://127.0.0.1:$vhost_port sftp://127.0.0.1:$vhost_port2",

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For hostbased authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'event:20 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo
    SFTPAuthorizedHostKeys file:~/.authorized_keys
  </IfModule>
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Server"

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
    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      for (my $i = 0; $i < 3; $i++) {
        my $ssh2 = Net::SSH2->new();

        unless ($ssh2->connect('127.0.0.1', $port)) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
        }

        unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
        }

        my $sftp_start_ts = [gettimeofday()];
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Opening SFTP channel...\n";
        }

        my $sftp = $ssh2->sftp();
        unless ($sftp) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
        }

        my $sftp_start_elapsed = tv_interval($sftp_start_ts);
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
        }

        my $path = 'proxy.conf';
        unless ($sftp->stat($path, 1)) {
          my ($err_code, $err_name) = $sftp->error();
          die("STAT $path failed: [$err_name] ($err_code)");
        }

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Closing SFTP channel...\n";
        }

        # To close the SFTP channel, we have to explicitly destroy the object
        $sftp = undef;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Disconnecting SSH...\n";
        }

        $ssh2->disconnect();
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_connect_policy_per_user_by_json {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerUser';
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxyReverseServers} = "sftp://127.0.0.1:$vhost_port sftp://127.0.0.1:$vhost_port2",

  my $user_path = File::Spec->rel2abs("$tmpdir/$setup->{user}-servers.json");
  if (open(my $fh, "> $user_path")) {
    print $fh "[ \"ftp://127.0.0.1:$vhost_port2\" ]\n";
    unless (close($fh)) {
      die("Can't write $user_path: $!");
    }

  } else {
    die("Can't open $user_path: $!");
  }

  my $uservar_path = File::Spec->rel2abs("$tmpdir/%U-servers.json");

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For hostbased authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  # Since we need multiple ProxyReverseServers directives, convert this
  # hashref into an arrayref.
  $proxy_config = config_hash2array($proxy_config);

  push(@$proxy_config, "ProxyReverseServers file:$uservar_path");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'event:20 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo
    SFTPAuthorizedHostKeys file:~/.authorized_keys
  </IfModule>
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Server"

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
    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      for (my $i = 0; $i < 3; $i++) {
        my $ssh2 = Net::SSH2->new();

        unless ($ssh2->connect('127.0.0.1', $port)) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
        }

        unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
        }

        my $sftp_start_ts = [gettimeofday()];
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Opening SFTP channel...\n";
        }

        my $sftp = $ssh2->sftp();
        unless ($sftp) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
        }

        my $sftp_start_elapsed = tv_interval($sftp_start_ts);
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
        }

        my $path = 'proxy.conf';
        unless ($sftp->stat($path, 1)) {
          my ($err_code, $err_name) = $sftp->error();
          die("STAT $path failed: [$err_name] ($err_code)");
        }

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Closing SFTP channel...\n";
        }

        # To close the SFTP channel, we have to explicitly destroy the object
        $sftp = undef;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Disconnecting SSH...\n";
        }

        $ssh2->disconnect();
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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

sub proxy_reverse_backend_ssh_connect_policy_per_group {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'proxy');

  my $vhost_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  $vhost_port += 12;
  my $vhost_port2 = $vhost_port - 7;

  my $cipher_algo = 'aes256-ctr';
  my $digest_algo = 'hmac-sha1';
  my $kex_algo = 'diffie-hellman-group14-sha1';

  my $proxy_config = get_reverse_proxy_config($tmpdir, $setup->{log_file},
    $vhost_port);
  $proxy_config->{ProxyReverseConnectPolicy} = 'PerGroup';
  $proxy_config->{ProxyOptions} = 'UseReverseProxyAuth';
  $proxy_config->{ProxySFTPCiphers} = $cipher_algo;
  $proxy_config->{ProxySFTPDigests} = $digest_algo;
  $proxy_config->{ProxySFTPKeyExchanges} = $kex_algo;
  $proxy_config->{ProxyReverseServers} = "sftp://127.0.0.1:$vhost_port sftp://127.0.0.1:$vhost_port2",

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/ssh_host_rsa_key");

  # For hostbased authentication
  my $rsa_priv_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key");
  my $rsa_pub_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/test_rsa_key.pub");
  my $rsa_rfc4716_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/t/etc/modules/mod_sftp/authorized_rsa_keys");

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_rfc4716_key, $authorized_keys)) {
    die("Can't copy $rsa_rfc4716_key to $authorized_keys: $!");
  }

  unless (chmod(0400, $rsa_priv_key)) {
    die("Can't set perms on $rsa_priv_key: $!");
  }

  $proxy_config->{ProxySFTPHostKey} = $rsa_priv_key;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'event:20 proxy:20 proxy.reverse:20 proxy.ssh:20 proxy.ssh.auth:20 proxy.ssh.disconnect:20 proxy.ssh.packet:20 proxy.ssh.kex:20 ssh2:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    SocketBindTight => 'on',

    IfModules => {
      'mod_proxy.c' => $proxy_config,

      'mod_sftp.c' => [
        'SFTPEngine on',
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
      ],

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

  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog $setup->{log_file}
    SFTPHostKey $rsa_host_key

    SFTPCiphers $cipher_algo
    SFTPDigests $digest_algo
    SFTPKeyExchanges $kex_algo
    SFTPAuthorizedHostKeys file:~/.authorized_keys
  </IfModule>
</VirtualHost>

<VirtualHost 127.0.0.1>
  Port $vhost_port2
  ServerName "Other Server"

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
    SFTPAuthorizedHostKeys file:~/.authorized_keys
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
      sleep(2);

      for (my $i = 0; $i < 3; $i++) {
        my $ssh2 = Net::SSH2->new();

        unless ($ssh2->connect('127.0.0.1', $port)) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
        }

        unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
        }

        my $sftp_start_ts = [gettimeofday()];
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Opening SFTP channel...\n";
        }

        my $sftp = $ssh2->sftp();
        unless ($sftp) {
          my ($err_code, $err_name, $err_str) = $ssh2->error();
          die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
        }

        my $sftp_start_elapsed = tv_interval($sftp_start_ts);
        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Sending SFTP STAT request ($sftp_start_elapsed since SFTP channel opened)...\n";
        }

        my $path = 'proxy.conf';
        unless ($sftp->stat($path, 1)) {
          my ($err_code, $err_name) = $sftp->error();
          die("STAT $path failed: [$err_name] ($err_code)");
        }

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Closing SFTP channel...\n";
        }

        # To close the SFTP channel, we have to explicitly destroy the object
        $sftp = undef;

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "Disconnecting SSH...\n";
        }

        $ssh2->disconnect();
      }
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
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
