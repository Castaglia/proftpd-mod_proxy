#!/usr/bin/env perl

use strict;

use Cwd qw(abs_path);
use File::Spec;
use Getopt::Long;
use Test::Harness qw(&runtests $verbose);

my $opts = {};
GetOptions($opts, 'h|help', 'C|class=s@', 'K|keep-tmpfiles', 'F|file-pattern=s',
  'V|verbose');

if ($opts->{h}) {
  usage();
}

if ($opts->{K}) {
  $ENV{KEEP_TMPFILES} = 1;
}

$verbose = 1;

if ($opts->{V}) {
  $ENV{TEST_VERBOSE} = 1;
}

# We use this, rather than use(), since use() is equivalent to a BEGIN
# block, and we want the module to be loaded at run-time.

if ($ENV{PROFTPD_TEST_DIR}) {
  push(@INC, "$ENV{PROFTPD_TEST_DIR}/t/lib");
}

my $test_dir = (File::Spec->splitpath(abs_path(__FILE__)))[1];
push(@INC, "$test_dir/t/lib");

require ProFTPD::TestSuite::Utils;
import ProFTPD::TestSuite::Utils qw(:testsuite);

# This is to handle the case where this tests.pl script might be
# being used to run test files other than those that ship with proftpd,
# e.g. to run the tests that come with third-party modules.
unless (defined($ENV{PROFTPD_TEST_BIN})) {
  $ENV{PROFTPD_TEST_BIN} = File::Spec->catfile($test_dir, '..', 'proftpd');
}

$| = 1;

my $test_files;

if (scalar(@ARGV) > 0) {
  $test_files = [@ARGV];

} else {
  $test_files = [qw(
    t/modules/mod_proxy.t
  )];

  # Now interrogate the build to see which module/feature-specific test files
  # should be added to the list.
  my $order = 0;

  my $FEATURE_TESTS = {
    't/modules/mod_proxy/ban.t' => {
      order => ++$order,
      test_class => [qw(mod_ban mod_proxy)],
    },

    't/modules/mod_proxy/redis.t' => {
      order => ++$order,
      test_class => [qw(feature_redis mod_proxy)],
    },

    't/modules/mod_proxy/reverse/ipv6.t' => {
      order => ++$order,
      test_class => [qw(feature_ipv6 mod_proxy)],
    },

    't/modules/mod_proxy/sql.t' => {
      order => ++$order,
      test_class => [qw(mod_proxy mod_sql mod_sql_sqlite)],
    },

    't/modules/mod_proxy/tls.t' => {
      order => ++$order,
      test_class => [qw(mod_proxy mod_tls)],
    },

    't/modules/mod_proxy/tls/redis.t' => {
      order => ++$order,
      test_class => [qw(feature_redis mod_proxy mod_tls)],
    },
  };

  my @feature_tests = testsuite_get_runnable_tests($FEATURE_TESTS);
  my $feature_ntests = scalar(@feature_tests);
  if ($feature_ntests > 1 ||
      ($feature_ntests == 1 && $feature_tests[0] ne 'testsuite_empty_test')) {
    push(@$test_files, @feature_tests);
  }
}

$ENV{PROFTPD_TEST} = 1;

if (defined($opts->{C})) {
  $ENV{PROFTPD_TEST_ENABLE_CLASS} = join(':', @{ $opts->{C} });

} else {
  # Disable all 'inprogress' and 'slow' tests by default
  $ENV{PROFTPD_TEST_DISABLE_CLASS} = 'inprogress:slow';
}

if (defined($opts->{F})) {
  # Using the provided string as a regex, and run only the tests whose
  # files match the pattern

  my $file_pattern = $opts->{F};

  my $filtered_files = [];
  foreach my $test_file (@$test_files) {
    if ($test_file =~ /$file_pattern/) {
      push(@$filtered_files, $test_file);
    }
  }

  $test_files = $filtered_files;
}

runtests(@$test_files) if scalar(@$test_files) > 0;

exit 0;

sub usage {
  print STDOUT <<EOH;

$0: [--help] [--class=\$name] [--verbose]

Examples:

  perl $0
  perl $0 --class foo
  perl $0 --class bar --class baz

EOH
  exit 0;
}
