#!/usr/bin/perl

use strict;
use warnings;

use FM::Debug;

package FM::Config;
require Exporter;
our $VERSION=1.0;
our @ISA=qw(Exporter);
our @EXPORT_OK=qw(new);

# все возможные опции
use fields qw(
  inb           outb
  origin        aka             domain
  umask         user            point_pipe
  logfile       debug           fido_charset
  mail_charset  config_charset  echo_to
  err           flavour         signature
);

# опции, которые представляют из себя массивы
my @array_fields=qw(
  origin        aka             signature
);

# опции, которые должны быть обязательно определены
my @must_fields=qw(
  aka             inb           outb
  domain          user          point_pipe
  logfile         fido_charset  mail_charset
  config_charset  echo_to       err
  flavour
);

my $config;

# конструктор
sub new($)
{
  return $config if defined $config;
  my ($class)=@_;
  my $file_name;
  
  die "Environment variable FMAIL_CONF must be defined" 
    unless exists $ENV{FMAIL_CONF};

  $file_name=$ENV{FMAIL_CONF};
  open my $file, "<", $file_name or die "Can not open '$file_name': $!";
  my $config=fields::new($class);

  CFG: while(<$file>)
  {
    s/#.*$//; s/\s+$//; s/^\s+//;
    next unless /(.*?)\s*=\s*(.*)/;
    my ($key, $value)=($1, $2);

    for (@array_fields)
    {
      if ($_ eq $key)
      {
        $config->{$_}=[] unless defined $config->{$_};
        push @{$config->{$_}}, $value;
        next CFG;
      }
    }

    $value=1 if $value=~/^(true|on|yes)/i;
    $value=0 if $value=~/^(false|off|no)/i;
    $config->{$key}=$value;
  }

  for (@must_fields)
  {
    die "Option '$_' must be defined" unless defined $config->{$_};
  }

  $config->work_known_options;
  $config;
}

# обрабатывает некоторые опции прямо при чтении конфига
sub work_known_options($)
{
  my ($self)=@_;
  $self=$config unless defined $self;
  umask $self->{umask} if defined $self->{umask};
  my $username=getlogin || getpwuid($<);
  $self->{point_pipe}=~s/%u/$username/g;
  $FM::Debug::LEVEL=$self->debug if defined $self->debug;
  $FM::Debug::LOGFILE=$self->logfile if defined $self->logfile;
}

# функции, которые возвращают одноименные field'ы 
sub AUTOLOAD($)
{
  our $AUTOLOAD;
  return if $AUTOLOAD=~/::DESTROY$/;
  my ($self)=@_;
  $self=$config unless defined $self;
  for (keys %{$self->[0]})
  {
    return $self->{$_} if $AUTOLOAD=~/$_$/;
  }
  die "Request for unknown fiels $AUTOLOAD";
}

1;
