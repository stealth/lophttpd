#!/usr/bin/perl

# frontend testcase for Location: redirects

use IO::Socket;

my $sock = new IO::Socket::INET->new(
	LocalPort => 8080,
	Proto => 'tcp',
	Reuse => 1,
	Type => SOCK_STREAM,
	Listen => 1) or die $!;

my $msg = "";
my $reply = "HTTP/1.1 300 Redirect blah\r\nX-blah: blahblah\r\n".
	    "Location:http://127.0.0.1:8080/\r\n\r\n";

while (1) {
	my $peer = $sock->accept();

	<$peer>;
	print $peer $reply;
	close($peer);
}


