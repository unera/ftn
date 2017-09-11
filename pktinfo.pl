#!/usr/bin/perl

BEGIN { push @INC, $1 if $0=~/(.*)\//; }

use warnings;
use strict;

# выводит подсказку как пользоваться pktinfo
sub usage()
{
  print <<end;
Usage: $0 -p path/to/file.pkt
for view fido packet information

-m    - display for messages info
-c    - show content messages
-k    - show kludges
end
  exit;
}


#====================================================================

our $PROGRAM='pktinfo';
our $VERSION=1.0;

use FTN::Packet;
use Getopt::Long;


my 
(
  $packet_name, $info_messages, $show_content,
  $show_kludges,
);

GetOptions
(
  'p=s'       =>  \$packet_name,
  m           =>  \$info_messages,
  c           =>  \$show_content,
  k           =>  \$show_kludges,
) and $packet_name or usage;

(-r $packet_name) or die "Can not find file: '$packet_name'";

{
  open my $packet, $packet_name 
    or die "Can not open file '$packet_name': $!";
  local $/;
  my $data=<$packet>;

  my $pkt=FTN::Packet->new;
  $pkt->parse_data($data);

  print '=' x 20, " Header packet $packet_name ", '=' x 20, "\n";
  printf "%15s: %s\n", 'from', $pkt->{from};
  printf "%15s: %s\n", 'to', $pkt->{to};
  printf "%15s: %s\n", 'time', $pkt->{time};
  printf "%15s: %s\n", 'baud rate', $pkt->{baud};
  printf "%15s: %s\n", 'password', "'$pkt->{password}'";
  printf "%15s: %04X\n", 'revision', $pkt->{rev};
  printf "%15s: %04X\n", 'product code', $pkt->{pcode};
  printf "%15s: %04X\n", 'capword', $pkt->{capword};
  
  my @messages=$pkt->messages;
  printf "%15s: %d\n", 'messages', scalar @messages;

  if ($info_messages and scalar @messages)
  {
    my $i=0;
    for (@messages)
    {
      $i++;
      print '-' x 15, " message [$i] ", '-' x 15, "\n";

      printf "%15s: %s\n", 'from', $_->{user_from};
      printf "%15s: %s\n", 'from addr', $_->{from};
      printf "%15s: %s\n", 'to', $_->{user_to};
      printf "%15s: %s\n", 'to addr', $_->{to};
      printf "%15s: %s\n", 'date', $_->{date};
      printf "%15s: %s\n", 'subject', $_->{subject};
      printf "%15s: %d\n", "length message", length $_->{text};
    
      ($show_kludges) and
        printf "%15s: %s\n", "kludge", $_ for (@{$_->{kludges}});
      
      if ($show_content)
      {
        my $text=$_->{text};
        $text=~s/\x0D/\n                 /g;
        printf "%15s: %s\n", 'message', $text;
      }
    }
  }
}

