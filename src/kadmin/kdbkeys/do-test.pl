#!/usr/local/bin/perl

#
# $Id$
#

$debug = $ARGV[1] || $ENV{'VERBOSE_TEST'};

die "Need a number.\n" if !$ARGV[0];

die "Neither \$TOP nor \$TESTDIR is set.\n" 
    if (! ($ENV{'TOP'} || $ENV{'TESTDIR'}));

$TESTDIR = ($ENV{'TESTDIR'} || "$ENV{'TOP'}/testing");
$INITDB = ($ENV{'INITDB'} || "$TESTDIR/scripts/init_db");

for ($i=0; $i<$ARGV[0]; $i++) {
    print "Trial $i\n" if $debug;

    system("$INITDB > /dev/null 2>&1") &&
	die "Error in init_db\n";

    open(KEYS,"./kdbkeys|") || die "Couldn't run ./kdbkeys: $!\n";
    while(<KEYS>) {
	next if ((!/^ovsec_adm\//) && (!/^krbtgt/));

	print if $debug;

	split;

	die "Duplicated key $_[0] = $_[1]\n" if $keys{$_[1]}++;
    }
    close(KEYS);
}
