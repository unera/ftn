#!/usr/bin/perl

use warnings;
use strict;

package FM::Debug;
require Exporter;
our $VERSION=1.0;
our @ISA=qw(Exporter);
our @EXPORT_OK=qw(debug $LEVEL $LOGFILE);
our @EXPORT=@EXPORT_OK;

our $LEVEL='info';
our $LOGFILE='stdout';

sub debug(@)
{
  my $level=pop;

  $LEVEL='warn' if $LEVEL=~/^warn/i;
  $LEVEL='err'  if $LEVEL=~/^err/i;
  
  my ($sl, $rl)=(2, 2);
  for (0 .. 3)
  {
    my @var=qw(err warn info deb);
    $sl=$_ if $LEVEL=~/$var[$_]/i;
    $rl=$_ if $level=~/$var[$_]/i;
  }

  return if $rl>$sl;

  my $log=\*STDOUT;
  if ($LOGFILE!~/^stdout$/i)
  {
    $log=undef;
    open $log, ">>", $LOGFILE or die "Can not open log file: '$LOGFILE': $!";
  }
  printf $log "%s [%s]: %s\n", scalar(localtime), $level, join('', @_);
}

1;
