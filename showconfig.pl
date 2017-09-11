#!/usr/bin/perl

use warnings;
use strict;

use Getopt::Long;
use FM::Config;

# показывает Usage
sub usage()
{
  print <<end;
Usage: $0 -c /path/to/config
end
  exit -1;
}


my $config_name;
GetOptions(
  'c=s'       =>  \$config_name,
) and $config_name or usage;

$ENV{FMAIL_CONF}=$config_name;


my $config=FM::Config->new;


for my $key (keys %{$config->[0]})
{
  if (ref $config->{$key} eq 'ARRAY')
  {
    printf "%15s: %s\n", $key, $config->{$key}->[0] 
      if defined $config->{$key}->[0];

    printf "%15s: %s\n", '', $config->{$key}->[$_]
      for (1 .. scalar(@{$config->{$key}})-1);
  }
  elsif (defined $config->$key)
  {
    printf "%15s: %s\n", $key, $config->$key;
  }
}
