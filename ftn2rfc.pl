#!/usr/bin/perl
BEGIN { unshift @INC, $1 if $0=~/^(.*)\//; }

use warnings;
use strict;

our $PROGRAM='ftn2rfc gate program';
our $VERSION=1.1;

use FM::Config;
use FM::Debug 'debug';
use FTN::Packet;
use FTN::Address;
use MIME::Lite;
use MIME::Words ':all';

$ENV{FMAIL_CONF}=$ARGV[0] if defined $ARGV[0];
my $conf=FM::Config->new;

# преобразует FIDO-шную дату в дату мыльную
sub ftn2rfc_date($)
{
  my ($date)=@_;
  return unless defined $date;
  return unless $date=~/(\d\d)\s(...)\s(\d\d)\s\s(\d\d:\d\d:\d\d)/;
  my ($day, $month, $year, $time)=($1, $2, $3, $4);
  if ($year>70) { $year="19$year"; }
  else { $year="20$year"; }

  return "$day $month $year $time";
}

# конвертирует пакет в rfc-сообщения
sub ftn2rfc($)
{
  my ($pkt)=@_;
  my @rfc_results;
  for my $msg ($pkt->messages)
  {
    my %rfc;
    
    my ($from, $to, $user_from, $user_to, $subject, $text, $date);
    
    $from=FTN::Address->new($msg->{from});
    $to=FTN::Address->new($msg->{to});
    $user_from=encode_mimeword($msg->{user_from}, 'B', $conf->fido_charset);
    $user_to=encode_mimeword($msg->{user_to}, 'B', $conf->fido_charset);
    $text=join("\n", split("\x0D", $msg->{text}));
#     $text=~s/\x8D/ /g;

    # тема
    $subject=$msg->{subject};
    $subject=~s/\s+$//;
    $subject=encode_mimeword($subject, 'B', $conf->fido_charset),

    # дата
    $date=ftn2rfc_date($msg->{date});
    $rfc{Date}=$date if defined $date;

    $from->domain=undef; $to->domain=undef;

    # записываем все клуджи
    # чтобы их можно было поглядеть
    my $kludgeno=0;
    for (@{$msg->{kludges}})
    {
      $kludgeno++;
      my $rfc_header=sprintf("X-Fido-Kludge-%02d", $kludgeno);
      $rfc{$rfc_header}=encode_mimeword($_, 'B', $conf->fido_charset);
    }

    my $area=$msg->kludge('AREA');
   
    # список рассылки
    if (defined $area)
    {
      $rfc{'List-Id'}="<$area>";
      $rfc{'List-Post'}=
        "<mailto:area-$area\@".$conf->domain."?X-Fido-To-Name=$user_from>";
      $rfc{'X-Fido-Area'}=$area;
    }
    else
    {
      $rfc{'X-Fido-Area'}='NETMAIL';
    }


    # теги поддержки тредов
    for ([REPLY=>'In-Reply-To'], [MSGID=>'Message-Id'])
    {
      my $kludge=$msg->kludge($$_[0]);
      next unless defined $kludge;
      
      my ($origaddr, $serial)=split(/\s+/, $kludge);
      $origaddr=join '', map { sprintf "%02X", $_ } unpack('C*', $origaddr);
      $rfc{$$_[1]}="<$serial\@$origaddr>";
    }
    
    # от кого идет сообщение
    $rfc{From}="$user_from <".$from->rfc.'@'.$conf->domain.'>';
    
    # fido-адреса откуда-куда
    $rfc{'X-Fido-To'}=encode_mimeword($to, 'B', $conf->fido_charset);
    $rfc{'X-Fido-From'}=encode_mimeword($from, 'B', $conf->fido_charset);
    $rfc{'X-Fido-To-Name'}=$user_to;
    $rfc{'X-Fido-From-Name'}=$user_from;

    # тема
    $rfc{Subject}=$subject;
  
    # по умолчанию почта идет юзеру первого aka
    $rfc{To}="$user_to <". (split(/\s+/, $conf->aka->[0]))[1].'>';
      
    
    # если to-адрес сообщения соответствует какому-то aka
    # то и выбираем его
    for my $aka (@{$conf->aka})
    {
      my ($faddr, $mail)=split(/\s+/, $aka);
      $rfc{To}="$user_to <".$mail.'>', last if ($faddr eq "$to");
    }
    
    # текст сообщения
    $rfc{Type}='text/plain; charset='.$conf->fido_charset;
    $rfc{Data}=$text;
    $rfc{Encoding}='base64';

    my $rfc_message=MIME::Lite->new(%rfc);
    $rfc_message->add($_ => $rfc{$_}) 
      for (grep(/^(List|In-Reply-To|Message-Id)/i, keys %rfc));

    push @rfc_results, $rfc_message->as_string;
  }
  @rfc_results;
}


debug "Start $PROGRAM, v$VERSION", 'info';

GATE: for my $pkt_file (glob($conf->inb . "/*.[pP][kK][tT]"))
{
  debug "process gate packet: $pkt_file", 'info';
  my $pkt=eval { FTN::Packet->new(file=>$pkt_file) };
  if ($@)
  {
    debug $@, 'error';
    next GATE;
  }

  unless (scalar $pkt->messages)
  {
    debug "$pkt_file not contain messages", "warn";
    next GATE;
  }
  debug "$pkt_file contain ", scalar $pkt->messages, " messages", 'debug';

  my @rfc=eval { ftn2rfc($pkt) };
  if ($@)
  {
    debug "Can not gate '$pkt_file': $@", 'error';
    next GATE;
  }
  
  for (@rfc)
  {
    my $procmail;
    unless(open $procmail, "|-", $conf->point_pipe)
    {
      debug "Can not start process '", $conf->point_pipe, "':$!", 'error';
      next GATE;
    }
    print $procmail $_;
    close $procmail;

    if ($?)
    {
      debug "Error send mail '|", $conf->point_pipe, "': $!", 'error';
      next GATE;
    }
  }
  
  unlink $pkt_file 
    or debug "Can not remove '$pkt_file': $!", 'error';
}

