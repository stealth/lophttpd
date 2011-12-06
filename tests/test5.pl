#!/usr/bin/perl

use IO::Socket;

my $host = shift || "127.0.0.1";

my $peer = new IO::Socket::INET->new(PeerAddr => $host,
	PeerPort => 80,
	Proto => 'tcp') or die $!;

my $msg=<<EOH;
GET /testfile HTTP/1.1\r\nRange: bytes=10-\r\nHost: $host\r\n\r\n
EOH

print $peer $msg;

while (1) {
	$msg = "";
	last if $peer->read($msg, 1024) == 0;
	print $msg;
}

close($peer);

