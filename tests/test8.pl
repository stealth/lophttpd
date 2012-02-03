#!/usr/bin/perl

use IO::Socket;

my $host = shift || "127.0.0.1";

my $peer = new IO::Socket::INET->new(PeerAddr => $host,
	PeerPort => 80,
	Proto => 'tcp') or die $!;

my $msg1=<<EOH;
GET /foo HTTP/1.1\r\nConnection: keep-alive\r\nHost: $host\r\n\r
EOH

my $msg2=<<EOH;
GET /bar HTTP/1.1\r\nConnection: keep-alive\r\nHost:        XYZ\r\n\r
EOH


print $peer $msg1;
print $peer $msg2;

while (1) {
	$msg = "";
	last if $peer->read($msg, 1024) == 0;
	print $msg;
}

close($peer);

