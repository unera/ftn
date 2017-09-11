#!/usr/bin/perl

BEGIN { unshift @INC, $1 if $0=~/^(.*)\//; }

use strict;
use warnings;

our $PROGRAM="rfc2ftn gate program";
our $VERSION=1.1;

use FM::Config;
use FM::Debug 'debug';
use MIME::Parser;
use FTN::Message;
use FTN::Packet;
use MIME::Words;
use Encode;
use MD5;
use Time::HiRes;
use File::Temp;


$ENV{FMAIL_CONF}=$ARGV[0] if defined $ARGV[0];
my $conf=FM::Config->new;

# декодирует хеадер переводя его в определенную кодировку
sub decode_header($$)
{
  my ($header, $charset)=@_;

  return unless defined $header;
  $charset='utf-8' unless defined $charset;

  my @hdrs=MIME::Words::decode_mimewords($header);

  $header='';

  for (@hdrs)
  {
    if (defined $$_[1])
    {
      $header.=decode($$_[1], $$_[0], Encode::FB_WARN);
    }
    else
    {
      $header.=$$_[0];
    }
  }

  $header=encode($charset, $header, Encode::FB_WARN);
  $header=~s/\s+$//;
  return $header;
}

# преобразует RFC-шную дату в FTN
sub rfc2ftn_date($)
{
  my ($date)=@_;
  unless (defined $date)
  {
    debug "Date in mail not defined, use NOW()", 'warn';
    my @dt=localtime; $dt[5]+=1900;
    $dt[4]=qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)[$dt[4]];
    $date=sprintf("%02d %s %d %02d:%02d:%02d", @dt[3, 4, 5], @dt[2, 1, 0]);
  }
  if ($date=~/(\d+)\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?:\d\d)?(\d\d)\s+(\d+):(\d+):(\d+)/)
  {
    my ($day, $month, $year, $hour, $min, $second)=($1, $2, $3, $4, $5, $6);
    
    for ($day, $hour, $min, $second, $year)
    {
      $_="0$_" while length($_)<2;
    }
    return "$day $month $year  $hour:$min:$second";
  }
  else
  {
    debug "Can not convert RFC822 datetime into FTN format", "error";
    my @time=localtime;
    my ($day, $month, $year, $hour, $min, $second)=
      ($time[3], $time[4], $time[5]-100, $time[2], $time[1], $time[0]);

    $month=qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)[$month];
    for ($day, $hour, $min, $second, $year)
    {
      $_="0$_" if $_<10;
    }
    return "$day $month $year  $hour:$min:$second";
  }
}

# возвращает новый msgid
sub generate_msgid
{
  return substr(MD5->hexhash(Time::HiRes::time), 0, 8);
}

# конвертирует сообщение в пакет ftn
# возвращает пакет
sub rfc2ftn($)
{
  my ($rfc_data)=@_;
  my $parser=MIME::Parser->new;
  $parser->output_to_core(1);
  $parser->tmp_to_core(1);
  my $entity=$parser->parse_data($rfc_data);
  my @parts=$entity->parts;

  my $from=$entity->head->get('From');
  my $to=$entity->head->get('To');
  my $fidoto=$entity->head->get('X-Fido-To-Name');
  my $subject=$entity->head->get('Subject');
  my $date=$entity->head->get('Date');
 
  $_=decode_header($_, $conf->fido_charset) 
    for ($from, $to, $fidoto, $subject);
  
  # вычисляем от какого AKA письмо (и соответственно на какой аплинк)
  $from=~/([\w\.-]+@[\w\.-]+)/;
  my $from_email=$1; $from_email=~tr/A-Z/a-z/;
  my ($aka, $aka_email, $uplink, $password)=split /\s+/, $conf->aka->[0];
  for (@{$conf->aka})
  {
    my ($caka, $cemail, $cup, $cpassword)=split /\s+/;

    $cemail=~tr/A-Z/a-z/;

    if ($cemail eq $from_email)
    {
      ($aka, $aka_email, $uplink, $password)=
        ($caka, $cemail, $cup, $cpassword);
    }
  }
  
  
  # создаем сообщение для пакета
  my $msg=FTN::Message->new;
  my $pkt=FTN::Packet->new;
  $msg->{user_from}=
    decode($conf->config_charset, $conf->user, Encode::FB_WARN);
  $msg->{user_from}=
    encode($conf->fido_charset, $msg->{user_from}, Encode::FB_WARN);

  $msg->{user_to}=$to;
  $msg->{user_to}=~s/['"><)(]/ /g;
  $msg->{user_to}=~s/\S+@\S+//g;
  $msg->{user_to}=~s/,.*$//;
  
  $msg->{user_to}=$fidoto if (defined $fidoto);
  $msg->{user_to}=~s/\s+/ /;
  $msg->{user_to}=~s/\s+$//;
  $msg->{user_to}=~s/^\s+//;
  
  $to=~/([\w\.-]+)@/;
  my $addr_to=$1;
  my $area;

  if ($addr_to=~/area-(\S+)/)
  {
    $area=$1;
    $msg->{user_to}=$conf->echo_to unless length $msg->{user_to};
    $msg->{to}->parse($uplink);
  }
  else
  {
    $msg->{to}->parse($addr_to);
    die "Address $addr_to - not valid fido address" 
      unless ($msg->{to}->is_valid);
  }

  $msg->{from}->parse($aka);

  $msg->{date}=rfc2ftn_date($date);
  $msg->{subject}=$subject;

  my ($body, $body_charset);
  if (scalar @parts)
  {
    $body=$parts[0]->bodyhandle;
    $body_charset=$parts[0]->head->get('Content-Type');
  }
  else
  {
    $body=$entity->bodyhandle;
    $body_charset=$entity->head->get('Content-Type');
  }

  $body_charset=~s/.*charset=([\w-]+).*/$1/;
  $body_charset=$conf->mail_charset unless defined $body_charset;
 
  die "Can not extract body from message" unless defined $body;

  # достаем текст сообщения
  # и кодируем его в fido-кодировку
  my @text=$body->as_lines;
  for(@text)
  {
    s/\s+$//;
    $_=decode($body_charset, $_, Encode::FB_WARN);
    $_=encode($conf->fido_charset, $_, Encode::FB_WARN);
  }

  # добавляем сигнатуру (если есть)
  if (defined $conf->signature)
  {{

    my $signature=$conf->signature->[int rand scalar @{$conf->signature}];
    defined $signature or last;
    $signature=decode($conf->config_charset, $signature, Encode::FB_WARN);
    $signature=encode($conf->fido_charset, $signature, Encode::FB_WARN);

    push @text, "... $signature";
  }}

  # добавляем origin (если есть)  
  if (defined $conf->origin)
  {
    my $origin=$conf->origin->[int rand scalar @{$conf->origin}];
    $origin=decode($conf->config_charset, $origin, Encode::FB_WARN);
    $origin=encode($conf->fido_charset, $origin, Encode::FB_WARN);
    $origin.=" ($msg->{from})";

    my $ua=$entity->head->get('User-Agent');
    $ua='' unless defined $ua;
    $ua=~s/\s+$//;
    push @text, "--- $ua";
    push @text, " * Origin: $origin";
  }
  $msg->{text}=join("\x0D", @text) . "\x0D";
  
  # клуджи сообщения
  # MSGID
  push @{$msg->{kludges}}, "MSGID: $msg->{from} " . generate_msgid;

  # достаем идентификатор сообщения на которое отвечаем
  # REPLY
  my $inreply=$entity->head->get('In-Reply-To');
  if (defined $inreply)
  {
    $inreply=~s/[><\s]//g; $inreply=~s/\s+$//;
    my ($serial, $address)=split("@", $inreply);
    
    if (length($serial)==8)
    {
      if (length($address)%2==0 and $address=~/^[0-9A-Fa-f]+$/)
      {
        $address=pack 'C*', map { hex $_ } $address=~/(..)/g;
        push @{$msg->{kludges}}, "REPLY: $address $serial";
      }
      else
      {
        my $orig_addr=FTN::Address->new($address);
        if ($orig_addr->is_valid)
        {
          push @{$msg->{kludges}}, "REPLY: $orig_addr $serial";
        }
        else
        {
          $address=~s/-\./@/g;
          $address=~s/--/-/g;
          push @{$msg->{kludges}}, "REPLY: $address $serial";
        }
        debug "reply to old-style In-Reply-To format: $inreply", 'error';
      }
    }
    else
    {
      debug "error serialno in In-Reply-To: '$inreply'", 'error';
    }
  }

  # INTL, FMPT, TOPT
  unless (defined $area)
  {
    my $intl="INTL $msg->{to} $msg->{from}";
    $intl=~s/\.\d+//g; $intl=~s/@\S+//g;
    push @{$msg->{kludges}}, "FMPT " . $msg->{from}->point;
    push @{$msg->{kludges}}, "TOPT " . $msg->{to}->point;
    push @{$msg->{kludges}}, $intl;
  }
  # AREA SEEN-BY
  else
  {
    push @{$msg->{kludges}}, "AREA:$area";
    my $seenby="$uplink";
    $seenby=~s/\d+://;
    $seenby=~s/\.\d+//;
    $seenby=~s/@.*//;
    push @{$msg->{kludges}}, "SEEN-BY: $seenby";
  }

  # замены символов
  for (qw(text user_from user_to subject))
  {
    $msg->{$_}=~s/\x8D/H/g;
  }

  $pkt->{from}=FTN::Address->new($msg->{from});
  $pkt->{to}->parse($uplink);
  push @{$pkt->{msg}}, $msg;
  $pkt->{password}=$password;
  $pkt;
}


# генерирует уникальное имя для пакета
sub gen_pack_name($)
{
  my ($dir)=@_;
  {
    my $name=sprintf("%s/%04x%04x.pkt", 
        $dir, int rand 0xFFFF, int rand 0xFFFF);
    redo if -e $name;
    return $name;
  }
}


# выход по какой-то ошибке
sub error_exit($$)
{
  my ($err_text, $input_data)=@_;
  my $file_name=File::Temp::tempnam($conf->err, "rfc_msg.");
  open my $file, ">", $file_name;
  print $file $input_data;
  close $file;
  debug "Error gate RFC to FTN message, message saved to $file_name", 
    "\n\t error: $err_text", 'error';
  exit -1;
}

debug "Start $PROGRAM v$VERSION", "info";
my $data; {  local $/; $data=<STDIN>; };

my $pkt=eval{rfc2ftn($data)};
error_exit($@, $data) if ($@);

my $out_name=gen_pack_name $conf->outb;
my $back_name=gen_pack_name $conf->inb;
my $req=sprintf("%s/%04x%04x.%slo", $conf->outb,
  $pkt->{to}->net, $pkt->{to}->node, $conf->flavour);

my $busy=sprintf("%s/%04x%04x.bsy", $conf->outb, 
  $pkt->{to}->net, $pkt->{to}->node);



# ждем снятия блокировки
sleep rand 10 while(-e $busy);
# создаем блокировку
{ 
  open my $hbusy, ">", $busy 
    or error_exit "Can not create file '$busy': $!", $data;
  close $hbusy;
  chmod 0664 => $busy;
}

my $hpkt;
unless (open $hpkt, '>', $out_name)
{
  unlink $busy;
  error_exit "Can not open file '$out_name': $!", $data;
}
print $hpkt $pkt;
close $hpkt;
chmod 0664 => $out_name;
debug "Saved packet into $out_name", 'info';

my $hlo;
unless (open $hlo, ">>", $req)
{
  unlink $busy;
  error_exit "Can not open file '$req': $!", $data;
}
print $hlo "^$out_name\n";
close $hlo;
chmod 0664 => $req;
unlink $busy;

my $hback;
unless (open $hback, ">", $back_name)
{
  error_exit "Can not create file '$back_name': $!", $data;
}
print $hback $pkt;
close $hback;
chmod 0664 => $back_name;
debug "Saved packet into $back_name", 'info';


