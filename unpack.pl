#!/usr/bin/perl

use strict;
use warnings;

BEGIN { unshift @INC, $1 if $0=~/^(.*)\//; }
use FM::Config;
use FM::Debug 'debug';

our $PROGRAM='fmail unpacker';
our $VERSION='1.0';

$ENV{FMAIL_CONF}=$ARGV[0] if defined $ARGV[0];
my $conf=FM::Config->new;

# упаковщики/распаковщики
# off - смещение в байтах от начала файла до сигнатуры
# sign - сигнатура
# cmd - команда распаковки в текущем каталоге
# list - команда получения списка файлов в архиве
#
# %a потом будет заменено на имя архива
my %packers=
(
  zip   =>  { 
              off=>0, sign=>"PK",       
              cmd=>"unzip -ojL %a", list=>"unzip -l %a",
            },
            
  arc   =>  { 
              off=>0, sign=>"\x1A",     
              cmd=>"arc eo %a",     list=>"arc l %a",
            },
            
  lha   =>  { 
              off=>2, sign=>"-lh",      
              cmd=>"lha eif %a",    list=>"lha l %a",
            },
            
  zoo   =>  { 
              off=>0, sign=>"ZOO",      
              cmd=>"zoo e: %a",     list=>"zoo l %a",
            },
            
  arj   =>  { 
              off=>0, sign=>"\xEA\x60", 
              cmd=>"unarj e %a",    list=>"unarj l %a",
            },
            
  Arj   =>  { 
              off=>0, sign=>"\x60\xEA", 
              cmd=>"unarj e %a",    list=>"unarj l %a",
            },
            
  rar   =>  { 
              off=>0, sign=>"Rar!",     
              cmd=>"rar e %a",      list=>"rar l %a",
            },
);

# сколько байт читать для того чтобы опознать что за архив
my $header_length=6;



# возвращает тип архива
sub get_arc_type($)
{
  my ($arc)=@_;
  open my $file, $arc or die "can not open $arc, $!";
  debug "opened file $arc", "debug";
  my $data;
  
  if (read($file, $data, $header_length)!=$header_length)
  {
    debug "Can not read $header_length bytes from $arc", "err";
    return;
  }
  
  for (keys %packers)
  {
    my $sf=substr $data, $packers{$_}->{off}, 
              length $packers{$_}->{sign};
    return $_ if $sf eq $packers{$_}->{sign};
  }
  return;
}

# распаковывает архив
sub unpack_arc($$)
{
  my ($arc, $atype)=@_;
  
  my $cmd_arc=$packers{$atype}->{cmd};
  $cmd_arc =~ s/%a/$arc/g;

  chdir $conf->inb;
  debug "Unpack command: $cmd_arc", 'debug';

  local $/;
 
  my $archout;
  unless (open $archout, "$cmd_arc 2>&1 |")
  {
    debug "Can non start unpacker: '$cmd_arc', error: $!", 'error';
    return;
  }
  my $res="\t" . <$archout>;
  $res=~s/\s*\n/\n\t/g;
  close $archout;

  if ($? == 0)
  {
    debug "unpacked $arc file", 'info';
    debug "remove file $arc from inbound", 'debug';
    unlink $arc;
  }
  else
  {
    debug "'$cmd_arc' return error string:\n$res", 'err';
    return;
  }
}

#====================================================================

debug "running unpacker inbound", 'info';

opendir my $inb, $conf->inb or die "Can not open dir ", $conf->inb;
my @files=grep(/\.(mo|tu|we|th|fr|sa|su).$/i, readdir($inb));
closedir $inb;

debug "in directory '" . $conf->inb . 
 "' found " . scalar(@files) . " archives", 'debug';

chdir $conf->inb;

for my $arc (@files)
{
  my $arc_type=get_arc_type($arc);
  unless (defined $arc_type)
  {
    debug "unknown archive type $arc, skipped", "warn";
    next;
  }

  unpack_arc($arc, $arc_type);
}
