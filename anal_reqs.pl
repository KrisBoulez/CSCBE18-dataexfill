use strict;
use warnings;

# file containing the data_requests
my $f = "data_requests";

my %h;

open F, $f or die "$!";

while (<F>) {
	chomp;
	my @t = unpack("(A2)*", $_);
	for my $t (@t) {
		$h{$t}++;
	}

}

foreach my $k (sort {$h{$a} <=> $h{$b}}  keys  %h) {
	print "$k $h{$k}\n";
}

close F;

# print out indication of where high-frequency duplets occur
open F, $f or die "$!";
while(<F>) {
	print;
	chomp;
	my @t = unpack("(A2)*", $_);
	for my $t (@t) {
		if ($h{$t} > 40) { 
			print "^ ";
		} else {
			print "  ";
		}
	}
	print "\n\n";
}
close F;

# perform frequency analyis on the 'xx' 'yy' and 'zz'  part
open F, $f or die "$!";
my (%xx, %yy);
while(<F>) {
	chomp;
	my @t = unpack("(A6)*", $_);
	for my $t (@t) {
		next unless ($t =~ /^(\w\w)(\w\w)\w{2}/);
		$xx{$1}++;
		$yy{$2}++;
	}
}

print "xx | #occ | decimal(xx)\n";
for my $k (sort keys %xx) {
	print "$k    $xx{$k}     ", hex($k), " \n";
}

print "\nyy | #occ | decimal(xx)\n------------------------\n";
for my $k (sort keys %yy) {
	print "$k    $yy{$k}     ", hex($k), " \n";
}

close F;



__END__

2e 12
05 12
02 12
41 12
16 13
36 15
28 16
23 16
13 17
22 17
08 17
0b 17
3d 18
07 19
18 20
32 21
25 23


34 31
14 38
2d 62
3f 65
47 67
04 74
45 80
4b 83
