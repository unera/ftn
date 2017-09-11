#!/usr/bin/perl

use FTN::Address;
use warnings;
use strict;

package FTN::Message;
require Exporter;
our @ISA=qw(Exporter);
our $VERSION=1.1;
our @EXPORT=qw(new);

use fields qw(
  from to user_from user_to subject date attr cost kludges text
);

use overload '""' => \&data;

# конструктор
sub new
{
  my $class=shift;
  my $self=fields::new($class);
  $self->{$_}='' for qw(user_from user_to subject text);
  $self->{$_}=FTN::Address->new for qw(from to);
  $self->{$_}=0 for qw(attr cost);
  $self->{kludges}=[];
  return $self;
}

# извлекает клуджи из сообщения
sub extract_kludges($)
{
  my ($self)=@_;
  my (@kludge, @text);
  my @lines=split("\x0D", $self->{text});

  while (defined ($_ = shift @lines))
  {
    if (/^\x01/)
    {
      s/^\x01//;
      push @kludge, $_;
      next;
    }
    push @text, $_;
  }

  shift @text while scalar @text and $text[0]=~/^\s*$/;
  pop @text while scalar @text and $text[-1]=~/^\s*$/;
  unshift @kludge, pop @text while scalar @text and $text[-1]=~/^SEEN-BY:/;
  unshift @kludge, shift @text if scalar @text and $text[0]=~/^AREA/;
  $self->{kludges}=\@kludge;
  $self->{text}=join("\x0D", @text);
}

# возвращает список клуджей с именем
sub kludge($$)
{
  my ($self, $kludge)=@_;

  my @kludges=grep /^$kludge(?:[:\s])/, @{$self->{kludges}};
  s/^$kludge(?:[:\s])\s*// for @kludges;
  s/\s+$// for @kludges;

  return @kludges if wantarray;
  return shift @kludges;
}


# заполняет поля сообщением из 
# пакета, если ошибка - возвращает 0
sub parse_pkt_data($$$$)
{
  my ($self, $data, $pfrom, $pto)=@_;
  return 0 if length($data)<2;
  return 0 if substr($data, 0, 2) eq "\0\0";
  
  die "Error unpack .pkt file" unless length($data)>34;

  my @hdr=unpack('S7 Z20 Z* Z* Z* Z*', $data);

  # параметры которые прямо можно сохранить 
  for ([attr=>5], [cost=>6], [date=>7], [user_to=>8],
        [user_from=>9], [subject=>10], [text=>11])
  {
    $self->{$$_[0]}=$hdr[$$_[1]];
  }

  $self->{text}=~s/\x0A//g;
  
  $self->extract_kludges;
 

  my $from=FTN::Address->new;
  my $to=FTN::Address->new;
 

  ($from->node, $to->node, $from->net, $to->net)=@hdr[1 .. 4];

  # определяем адреса из клуджей
  {
    my $topt=$self->kludge('TOPT');
    $to->point=$topt if defined $topt;
    my $fmpt=$self->kludge('FMPT');
    $from->point=$fmpt if defined $fmpt;
    
    # определяем адреса назначения и исходный из кладжа INTL
    my $intl=$self->kludge('INTL');
    if (defined $intl and $intl=~/(\d+:\d+\/\d+)\s+(\d+:\d+\/\d+)/)
    {
      my ($tp, $fp)=($to->point, $from->point);
      $to->parse($1); $from->parse($2);
      ($to->point, $from->point)=($tp, $fp);
      last;
    }

    # определяем исходный адрес из кладжа MSGID
    my $msgid=$self->kludge('MSGID');
    if (defined $msgid and $msgid=~/(\d+:\d+(?:\/\d+)?(?:\.\d+)?)(?:@.*?)?\s/)
    {
      $from->parse($1);
      last;
    }
    
    # берем зону и поинта из заголовков пакета
    # а сеть и нода из заголовков сообщения
    $from->zone=$pfrom->zone if $pfrom->zone;
    $from->point=$pfrom->point if $pfrom->point;
    $to->zone=$pto->zone if $pto->zone;
    $to->point=$pto->point if $pto->point;
  }
  
  $self->{from}=$from;
  $self->{to}=$to;

  my $area=$self->kludge('AREA');

  my $length=34;
  $length+=1+length($_) for @hdr[8 .. 11];
  return $length;
}

# упаковывает сообщение в двоичные данные (пакет)
# для записи
sub data($)
{
  my ($self)=@_;

  my @data;

  @data[0 .. 10]=
  (
    2,
    $self->{from}->node, 
    $self->{to}->node, 
    $self->{from}->net, 
    $self->{to}->net,
    $self->{attr}, 
    $self->{cost}, 
    $self->{date},
    $self->{user_to}, 
    $self->{user_from}, 
    $self->{subject},
  );

  my $text=$self->{text};
  my @lines=split("\x0D", $text);
  s/\s+$// for @lines;
  pop @lines while scalar @lines and $lines[-1]=~/^\s*$/;
  
  for (@{$self->{kludges}})
  {
    if (/^SEEN-BY/)
    {
      push @lines, $_;
    }
    elsif (/^AREA:/)
    {
      next;
    }
    else
    {
      unshift @lines, "\x01$_";
    }
  }
  
  my $area=$self->kludge('AREA');
  unshift @lines, "AREA:$area" if defined $area;
  push @data, join("\x0D", @lines);

  return pack 'S7 Z20 Z* Z* Z* Z*', @data;
}

1;
