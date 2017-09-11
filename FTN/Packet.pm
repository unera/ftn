#!/usr/bin/perl

use strict;
use warnings;

use FTN::Message;
use FTN::Address;

package FTN::Packet;
require Exporter;
our $VERSION=1.1;
our @ISA=qw(Exporter);
our @EXPORT=qw(new);
use fields qw(
  from to time baud pcode rev password capword msg
);

use overload '""' => \&data;

# конструктор
sub new
{
  my $class=shift;
  my %opts=@_;
  my $self=fields::new($class);
  $self->{msg}=[];
  $self->{$_}=FTN::Address->new for qw(from to);
  
  $self->parse_data($opts{data}) if exists $opts{data};
  $self->parse_file($opts{file}) if exists $opts{file};
  return $self;
}

# возвращает пакет в виде двоичных данных
sub data($)
{
  my ($self)=@_;
  my $from=FTN::Address->new($self->{from});
  my $to=FTN::Address->new($self->{to});

  my @data;
  my @time=localtime;
  $time[5]+=1900;

  my $password=$self->{password};
  $password="\0" x 8 unless defined $password;

  @data[0 .. 26]=
  (
    $from->node, 
    $to->node,
    @time[reverse 0 .. 5],
    $self->{baud},
    2,
    $from->net, 
    $to->net,
    0,
    0,
    $password,
    $from->zone, 
    $to->zone,
    0,
    0x0100,
    0,
    0,
    0x0001,
    $from->zone, 
    $to->zone,
    $from->point, 
    $to->point,
    0
  );

  for (@data[0 .. 26])
  {
    $_=0 unless defined $_;
  }

  my $packet=pack('S12 C2 a8 S4 C2 S5 L', @data);
#   my $packet=pack('S12 C2 Z8 S4 C2 S5 L', @data);
  $packet.=$_ for $self->messages;
  return "$packet\0\0";
}

# возвращает список сообщений в пакете
sub messages($)
{
  my ($self)=@_;
  return @{$self->{msg}};
}

# загружает пакет из буфера
sub parse_data($$)
{
  my ($self, $data)=@_;
  
  die "Error format .pkt" unless length($data)>58;
  
  my @hdr=unpack('S12 C2 Z8 S4 C2 S5 L', $data);
  $self->{capword}=$hdr[21];
  {
    my $vcw=$hdr[18];
    $vcw=($vcw>>8)|(($vcw&0xFF)<<8);
    $self->{capword}=0 unless $vcw==$self->{capword};
  }

  $self->{$_}->parse('0/0') for qw(from to);

  ($self->{from}->node, $self->{to}->node)=@hdr[0, 1];
  ($self->{from}->net, $self->{to}->net)=@hdr[10, 11];
  $self->{from}->net=$self->{to}->net if $self->{from}->net==0xFFFF;

  ($self->{from}->zone, $self->{to}->zone)=@hdr[15, 16];

  if ($self->{capword})
  {
    $self->{from}->zone=$hdr[22] if $hdr[22];
    $self->{to}->zone=$hdr[23] if $hdr[23];
    ($self->{from}->point, $self->{to}->point)=@hdr[24,25];
  }

  $self->{pcode}=$hdr[12]|($hdr[19]<<8);
  $self->{baud}=$hdr[8];
  $self->{password}=$hdr[14];
  $self->{rev}=($hdr[13]<<8)|$hdr[20];

  my ($year, $month, $day, $hour, $minute, $second)=@hdr[2 .. 7];
  $month=qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)[$month];
  for ($day, $hour, $minute, $second)
  {
    $_="0$_" if $_<10;
  }
  $self->{time}="$day $month $year $hour:$minute:$second";

  $self->{msg}=[];

  $data=substr($data, 58);
  my @messages;
  
  {
    my $msg=FTN::Message->new;
    my $len=$msg->parse_pkt_data($data, $self->{from}, $self->{to});
    if ($len)
    {
      push @messages, $msg;
      $data=substr($data, $len);
      redo;
    }
  }
  $self->{msg}=\@messages;
}

# парсит файл
sub parse_file($$)
{
  my ($self, $file_name)=@_;
  (-r $file_name) or die "Can not find readable file '$file_name'";
  open my $pkt, $file_name or die "Can not open file '$file_name': $!";
  my $data;
  {
    local $/;
    $data=<$pkt>;
  }
  close $pkt;
  $self->parse_data($data)
}

1;
