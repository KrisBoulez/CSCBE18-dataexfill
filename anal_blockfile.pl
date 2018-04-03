use strict;
use warnings;

# analyse blockfile for the number of occurences of key / value pairs

# blockfile to analyse
my $bf = 'data/312304';

open BF, $bf or die "$!";

my %tags;

while(<BF>) {
	next unless /^\s*"(\S+)":\S*/;
	$tags{$1}++;
}

for my $k (sort { $tags{$a} <=> $tags{$b} } keys %tags) {
	printf("%-14s %d\n", $k, $tags{$k});
}
