# FTN/Address.pm

package FTN::Address;
require Exporter;

our @ISA=qw(Exporter);
our $VERSION=1.0;
our @EXPORT=qw(new);

use fields qw(zone net node point domain valid);

use overload '""' => \&get, '${}' => \&get;

sub new
{
  my ($class, $addr)=@_;

  
  $addr=$addr->get if ref($addr) eq __PACKAGE__;
  $addr="0:0/0.0" unless defined $addr;

  my $self=fields::new($class);
  $self->parse($addr);
  $self;
}

# парсит строку с адресом 
sub parse($$)
{
  my ($self, $addr)=@_;
  $self->{$_}=0 for (qw(zone net node point));
  $self->{domain}=undef;
  $addr=~s/['"<>\s]//g;
  
  $self->{valid}=0;
  $addr=~/(?:\d+:)?\d+\/\d+(?:\.\d+)?(?:@.*)?/ and $self->{valid}=1;
  $addr=~/(?:p\d+\.)?f\d+\.n\d+\.(?:z\d+)?/ and $self->{valid}=1;
  
  $self->{domain}=$1 if $addr=~/@(.*)$/;
  $addr=~s/@.*$// if defined $self->domain;
  
  $self->{zone}=$1 
    if $addr=~/(\d+):/ or $addr=~/z(\d+)/;
  $self->{net}=$1 
    if $addr=~/:(\d+)/ or $addr=~/(\d+)\// or $addr=~/n(\d+)/;
  $self->{node}=$1 
    if $addr=~/\/(\d+)/ or $addr=~/f(\d+)/;
  $self->{point}=$1 
    if $addr=~/\.(\d+)/ or $addr=~/p(\d+)/;

}

# адрес можно устанавливать по отдельности для каждого элемента
sub zone($)    :lvalue  { my ($self)=@_; $self->{zone} }
sub net($)     :lvalue  { my ($self)=@_; $self->{net} }
sub node($)    :lvalue  { my ($self)=@_; $self->{node} }
sub point($)   :lvalue  { my ($self)=@_; $self->{point} }
sub domain($)  :lvalue  { my ($self)=@_; $self->{domain} }

sub is_valid($) { my ($self)=@_; $self->{valid} }

# возвращает канонический адрес
sub get($)
{
  my ($self)=@_;
  my $addr='';
  $addr.="$self->{zone}:" if $self->zone;
  $addr.="$self->{net}/$self->{node}";
  $addr.=".$self->{point}" if $self->point;
  $addr.="\@$self->{domain}" if defined $self->domain;
  $addr;
}

# возвращает RFC-форму адреса
sub rfc($)
{
  my ($self)=@_;
  my $addr='';
  $addr.='p' . $self->point if $self->point;
  $addr.='.' if length $addr;
  $addr.='f' . $self->node . '.n' . $self->net;
  $addr.='.z' . $self->zone if $self->zone;

  $addr.='@' . $self->domain if defined $self->domain;

  $addr;
}

1;
