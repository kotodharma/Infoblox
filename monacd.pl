#!/opt/perl/bin/perl
=pod

=head1 NAME

monacd.pl - DNS Anycast Monitor daemon

=cut
use strict;
use FindBin ();
use Getopt::Std;
use File::Spec::Functions qw(catfile);
use IO::Handle;
use Infoblox;

my %Severity = qw(EMERG 0 ALERT 1 CRIT 2 ERR 3 WARN 4 NOTICE 5 INFO 6 DEBUG 7);
my(%opts, %Conf, @anycasts, %Allstat, $logfh);
sub logg;  ## needed to permit nice, clean syntax for logg
open($logfh, ">&STDERR") or die "Cannot dup STDERR";

getopts('c:', \%opts);
read_config();
initialize();

my $loglevel = $Conf{loglevel};

map { $SIG{$_} = \&terminate } qw(INT QUIT TERM TSTP ABRT);
$SIG{HUP} = \&hup_handler;

while (1) {
    query_anycasts();
    store_status();
    sleep ($Conf{query_interval} || 60);
}
## END OF MAIN CODE

#####################################################################
##
#####################################################################
sub query_anycasts {

    foreach my $sec (@anycasts) {
        my $ac_server = $sec->name;
        logg 'INFO', sprintf "Getting bind status on %s (%s)", $ac_server, $sec->ipv4addr;

        eval {
            my @rndc_out = qx(/usr/sbin/rndc -s $ac_server status);
            if ($?) {
                die "$!";
            }
            my %status = map { chomp; split /: | is / } @rndc_out;
            $ac_server =~ s/\..*$//;   ## reduce name to non-FQDN for compactness
            $Allstat{$ac_server} = { %status };
            ## Rename field 'server' to 'status'
            $Allstat{$ac_server}{status} = delete $Allstat{$ac_server}{server};
        };
        if ($@) {
            logg 'ALERT', sprintf "RNDC status failure: %s: $@", $sec->name;
            $@ =~ s/\s+/ /g;   ## make sure it's safe for tab-delim file
            $Allstat{$ac_server}{status} = "rndc: $@";
        }
    }
}

#####################################################################
##
#####################################################################
sub store_status {
    my $file = $Conf{statusfile_path};
    my $statustext;
    foreach my $server (sort keys %Allstat) {
        my %stats = %{ $Allstat{$server} };
        my @row = ($server, map { $_, $stats{$_} } (sort keys %stats));
        $statustext .= join("\t", @row) . "\n";
    }
    eval {
        open(STATUS, '>'.$file) or die "Cannot open status file $file for write: $!";
        print STATUS $statustext;
        close STATUS;
    };
    if ($@) {
        logg 'ERR', "Create status file: $@";
        return 0;
    }
}

#####################################################################
##
#####################################################################
sub read_config {
    my($hupped) = @_;
    my $file = $opts{c} || catfile($FindBin::Bin, 'monac.conf');
    my $conftext;
    eval {
        local $/ = undef;
        open(CONF, $file) or die "Cannot open config file $file for read: $!";
        $conftext = <CONF>;
        close CONF;
    };
    if ($@) {
        my $msg = "Read config: $@";
        logg 'ERR', $msg;
        return 0;
    }
    eval $conftext;  ## incorporate the config code
    if ($@) {
        my $msg = "Read config: code error: $@";
        logg 'ERR', $msg;
        return 0;
    }
    return 1;
}

#####################################################################
##
#####################################################################
sub initialize {
    my($hupped) = @_;

    logg 'INFO', 'Monac initializing ===================';

    my $session = new Infoblox::Session (%{ $Conf{bloxcreds} });
    die $session->status_detail if $session->status_code;
    logg 'INFO', "Authenticated to " . $Conf{bloxcreds}{master} . " as " . $Conf{bloxcreds}{username};

    my($defgroup) = $session->get( object => 'Infoblox::Grid::DNS::Nsgroup', name => 'default' );
    @anycasts = grep { $_->stealth eq 'true' } @{ $defgroup->secondaries };
    die $session->status_detail if $session->status_code;
    logg 'INFO', sprintf "NS group 'default' has %d anycast stealth secondaries", scalar(@anycasts);
}

########################################################################
##
########################################################################
sub terminate {
    my($sig) = @_;
    logg 'ALERT', "Terminating on SIG$sig";
    $logfh->close if ref($logfh) && $logfh->opened;
    exit;
}

########################################################################
##
########################################################################
sub hup_handler {
    my($sig) = @_;
    logg 'ALERT', "Received SIG$sig !";
    logg 'NOTICE', "Re-reading config...";
    if (read_config(1)) {
        logg 'NOTICE', "Re-initializing...";
        initialize(1);
    }
}

########################################################################
##
########################################################################
sub logg {
    my $level = shift;
    my $nlevel = $Severity{$level} || int($level);
    if ($nlevel <= $loglevel) {
        my $ts = scalar(localtime());
        printf $logfh "%s %-12s @_\n", $ts, "LOG($level):";
    }
}

__END__
=pod

=head1 SYNOPSIS

monacd.pl [-c <path>]

Options:
   -c <path>    path to config file (default = ./monac.conf)

=head1 SIGNAL HANDLING

The program will terminate gracefully if it receives any of SIGINT, SIGQUIT, SIGTERM, SIGTSTP
or SIGABRT.

On receipt of SIGHUP, the program will reread its configuration file and reinitialize itself.

=head1 AUTHOR

David J. Iannucci <dji@uen.org>

=head1 VERSION

 $Id: monacd.pl,v 1.3 2011/02/02 18:44:50 dji Exp $

=cut
