#!/usr/bin/perl

use strict;
use warnings;

use FM::Debug 'debug';
use FTN::Packet;

die "Usage $0 1.pkt 2pkt ... for start test" unless @ARGV;

for (@ARGV)
{
  my $info=`./pktinfo.pl -m -k -p $_`; 
  my $pkt=FTN::Packet->new(file=>$_);

  open my $tmp, ">1.pkt" or die "can not open 1.pkt";
  print $tmp $pkt;
  close $tmp;

  $info.=`./pktinfo.pl -m -k -p 1.pkt`;
  unlink '1.pkt';
  print $info, "\n";
}
