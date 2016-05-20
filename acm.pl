=pod

=head1 NAME

acm - DNS Anycast Manager

=head1 SYNOPSIS

acm.pl [-l logfile_path] [-L loglevel] [-c configfile_path] [-t <ev>] [-h]

    Default logfile is STDERR
    Default loglevel is WARN (4)
    Default configfile_path is ./acm.conf (i.e. same dir where acm.pl lives)

    -t <ev>  Testing mode: validate operation against Infoblox appliance.
             Argument <ev> is the name of an event (to be generated using
             default arguments), or 'all' to run the full default test script.
    -h       Displays the man page

=cut

use strict;     ## remove this line under penalty of death :-|
use Getopt::Std;
use FindBin ();
use File::Spec::Functions qw(catfile);
use IO::Handle;
use Infoblox;
use Net::OpenSSH;
use File::Tail;

my %Severity = qw(EMERG 0 ALERT 1 CRIT 2 ERR 3 WARN 4 NOTICE 5 INFO 6 DEBUG 7);
my(%opts, %Conf, $logfh, $loglevel, $tail, $dns, @allnsgroups, @bindservers);
our($session, $defgroup);
our $wait = 8;  ## default max seconds to wait for logs to appear (testing only)
sub logg;       ## needed to permit pretty syntax for logg

getopts('l:L:c:t:h', \%opts);
if ($opts{h}) {
    exec('perldoc', '-T', catfile($FindBin::Bin, $FindBin::Script));
    ## NOT REACHED - END OF PROGRAM
}
my $testing = $opts{t};

logg_init();  ## initialize logging
if (exists($opts{t}) && $testing eq '') {
    logg 'ERR', '-t requires an explicit argument';
    die;
}
read_config();
initialize();

our(%Events, @AllTests);
eval { require $Conf{eventsfile_path}; }; ## load events and tests
if ($@) {
    logg 'ERR', "Error in events file:\n$@";
    die;
}

map { $SIG{$_} = \&terminate } qw(INT QUIT TERM TSTP ABRT);
$SIG{USR1} = \&usr1_handler;
$SIG{HUP} = \&hup_handler;

if ($testing) {
    $loglevel = $Severity{DEBUG};  ## maximum logging for tests
    run_tests();
    exit;
    ## NOT REACHED - END OF PROGRAM
}

startup_check();

## MAIN LOOP

logg 'INFO', sprintf "Now starting to watch the log on %s...", $Conf{syslog_path};
while (1) {
    while (my $line = get_log()) {
        handle_events($line);
    }
    ## This point should never be reached
    logg 'ALERT', "Log tail loop ended!";
    sleep 10;  ## if File::Tail fails miserably, don't fill up logs too fast
}
## END OF MAIN CODE

#####################################################################
## Collect the next line from the Infoblox audit log
#####################################################################
sub get_log {
    my($timeout) = @_;
    my $line;

    eval {
        local $SIG{ALRM} = sub { logg('DEBUG', 'timeout!'); die };
        alarm $timeout if $timeout;
        $line = $tail->read;
        alarm 0;
    };
    return $line;
}

#####################################################################
## Scrape an audit log line to find a relevant event
#####################################################################
sub handle_events {
    my($line) = @_;
    my $code;

    EVENT: foreach my $evname (keys %Events) {
        my $ev = $Events{$evname};
        my $match = $ev->{match};
        my @alternates = ref($match) eq 'ARRAY' ? @{ $match } : $match;

        foreach my $regex (@alternates) {
            if ($line =~ $regex) {
                eval {
                    no strict 'refs';  ## only needed to enable the following map to work
                    my @tokens = map { ${$_} } 0..99;   ## collect up all regex captures ($1, $2, etc)
                    $code = $ev->{handler}->(@tokens);  ## and pass them into handler routine call
                };
                if ($@) {
                    logg 'CRIT', "Event handler failure ($evname): $@";
                }
                last EVENT; ## there should only be one event that matches
            }
        }
    }
    return $code;
}

#####################################################################
## Update named.conf file on bindservers with new version
#####################################################################
sub update_bindservers {
    return if $testing;
    my($newconf) = @_;

    my $conf = $newconf || build_namedconf();
    if ($conf) {
        spam_newconf($conf);
    }
    else {
        logg 'CRIT', "Cannot generate named.conf - skipping this event";
    }
}

#####################################################################
## Create new named.conf text by querying Infoblox master
#####################################################################
sub build_namedconf {
    logg 'INFO', "Building named.conf...";
    my @zones;
    eval {
        logg 'INFO', "Getting all zones...";
        @zones = $session->get( object => 'Infoblox::DNS::Zone' );
        die $session->status_detail if $session->status_code;
        logg 'INFO', "...done.";
    };
    if ($@) {
        logg 'ALERT', "Get zones: $@";
        return undef;
    }
    my $master = $defgroup->primary->ipv4addr;
    my $conf_templ;
    eval {
        local $/ = undef;  ## read whole file as one blob of text
        open(HEADER, $Conf{headerfile_path}) or die "Cannot open: $!";
        $conf_templ = <HEADER>;
        close HEADER;
    };
    if ($@) {
        logg 'ALERT', "Header file $Conf{headerfile_path}: $@";
        return undef;
    }
    my $conf = sprintf $conf_templ, scalar(localtime()), gen_listen_on(), gen_allow_xfer();

    foreach my $zone (sort by_objname @zones) {
        my $name = standardize_name($zone->name);
        next if $name =~ /0.127.in-addr.arpa/;    ## omit loopback zone

        $conf .= qq(zone "$name" in {\n);
        $conf .= qq(\ttype\tslave;\n);
        $conf .= qq(\tfile\t"$name.bak";\n);
        $conf .= qq(\tmasters\t{ $master; };\n);
        if (my $ax_list = $zone->allow_transfer) {
            my @ax_list = @{ $ax_list };
            $conf .= sprintf "\tallow-transfer\t{ %s };\n",
                join(' ', map { "$_;" } @ax_list);
        }
        $conf .= "};\n\n";
    }
    eval {
        open(CUR, '>'.$Conf{local_namedconf_path}) or die "Cannot open file: $!";
        print CUR $conf;
        close CUR;
        logg 'INFO', "Stored named.conf locally in " . $Conf{local_namedconf_path};
    };
    if ($@) {
        logg 'ERR', "Store current named.conf: " . $Conf{local_namedconf_path} . ": $@";
    }
    logg 'INFO', "...done building named.conf";
    return $conf;
}

#####################################################################
## Physically copy named.conf file to remote bindservers
#####################################################################
sub spam_newconf {
    my($config) = @_;

    foreach my $sec (sort by_objname @bindservers) {
        my $ac_server = $sec->name;
        logg 'NOTICE', sprintf "Updating named.conf on %s (%s)", $ac_server, $sec->ipv4addr;

        eval {
            my $ssh = new Net::OpenSSH ($ac_server, %{ $Conf{sshparams} });
            if ($ssh->error) {
                die "new connection: " . $ssh->error;
            }

            my($in, $pid) = $ssh->pipe_in("/bin/cat > " . $Conf{remote_namedconf_path})
                or die "open pipe_in: " . $ssh->error;
            print $in $config;
            unless (close $in) {
                die "close pipe_in: " . $ssh->error;
            }
            logg 'INFO', "Transferred named.conf to $ac_server:" . $Conf{remote_namedconf_path};
        };
        if ($@) {
            logg 'ALERT', sprintf "SSH failure: %s: $@", $sec->name;
        }
    }
}

#####################################################################
## Send rndc reload command to all remote bindservers
#####################################################################
sub reload_bindservers {
    return if $testing;

    foreach my $sec (sort by_objname @bindservers) {
        my $ac_server = $sec->name;
        logg 'NOTICE', sprintf "Reloading bind on %s (%s)", $ac_server, $sec->ipv4addr;

        eval {
            my($rndc_reload) = qx(/usr/sbin/rndc -s $ac_server reload);
            if ($?) {
                die "rndc reload: $!";
            }
            chomp $rndc_reload;
            logg 'INFO', "RNDC reload: $rndc_reload";
        };
        if ($@) {
            logg 'ALERT', sprintf "RNDC failure: %s: $@", $sec->name;
        }
    }
}

#####################################################################
## Generate listen-on list from default NS group
#####################################################################
sub gen_listen_on {
    ## Listen-on contains all anycast IPs + the loopback interface
    my @addrs = ('127.0.0.1');
    push(@addrs, map { $_->ipv4addr } @{ $defgroup->secondaries });
    join(' ', map { "$_;" } @addrs);
}

#####################################################################
## Generate allow-transfer list from Infoblox's system-wide config
#####################################################################
sub gen_allow_xfer {
    my @addrs = @{ $dns->allow_transfer };
    join(' ', map { "$_;" } sort @addrs);
}

#####################################################################
## Convert CIDR-notated rev zones to traditional in-addr.arpa format
#####################################################################
sub standardize_name {
    my $z = shift;
    return $z if $z =~ m#[^0-9./]#;         ## Beware: this assumes reverses are ipv4!
    my($ip, $b) = split m#[/]#, $z, 2;
    my @octs = reverse(split /[.]/, $ip, 4);
    my $numshifts = 4 - int($b / 8);        ## assumes CIDR size is /8, /16, or /24
    map { shift @octs } 1..$numshifts;      ## really just a loop
    join('.', @octs) . '.in-addr.arpa';
}

#####################################################################
## Read the configuration file, (re)establishing %Conf hash
#####################################################################
sub read_config {
    my($hupped) = @_;
    my $file = $opts{c} || catfile($FindBin::Bin, 'acm.conf');
    my $conftext;
    eval {
        local $/ = undef;
        open(CONF, $file) or die "Cannot open config file $file for read: $!";
        $conftext = <CONF>;
        close CONF;
    };
    if ($@) {
        my $msg = "Read config: $@";
        $hupped ? logg('ERR', $msg) : die $msg;
        return 0;
    }
    eval $conftext;  ## incorporate config code into execution context
    if ($@) {
        my $msg = "Read config: code error: $@";
        $hupped ? logg('ERR', $msg) : die $msg;
        return 0;
    }
    return 1;
}

#####################################################################
## Initialize logging
#####################################################################
sub logg_init {
    my($hupped) = @_;

    my $ll = $opts{L} || $Conf{loglevel} || 'WARN';
    $loglevel = $Severity{$ll} || int($ll) || die "Invalid loglevel ($ll)";

    eval {
        my $newfh;
        my $f = $opts{l} || $Conf{acmlog_path} || 'STDERR';
        if ($f eq 'STDERR') {
            open($newfh, ">&$f") or die "Cannot dup $f: $!";
        }
        else {
            open($newfh, ">>$f") or die "Cannot open logfile $f to append: $!";
        }
        $logfh->close if ref($logfh) && $logfh->opened;  ## close old handle
        $logfh = $newfh;       ## replace with new handle
        $logfh->autoflush(1);  ## make log output unbuffered
        logg 'INFO', "Writing logs to $f";
    };
    if ($@) {
        my $msg = "Logg_init: $@";
        $hupped ? logg('ERR', $msg) : die $msg;
    }
    logg 'ALERT', "NOW using log severity level $ll ($loglevel)";
}

#####################################################################
## Initialize everything else
#####################################################################
sub initialize {
    my($hupped) = @_;

    logg_init($hupped);

    logg 'INFO', 'ACM initializing ===================';
    eval {
        $tail->DESTROY if ref $tail;
        $tail = new File::Tail (
            name => $Conf{syslog_path},
            interval => 1,
            maxinterval => 3,
            resetafter => 30
        ) or die "Cannot create new file tail object for " . $Conf{syslog_path};
    };
    if ($@) {
        my $msg = "Initialize: $@";
        $hupped ? logg('CRIT', $msg) : die $msg;
        return;
    }

    $session = new Infoblox::Session (%{ $Conf{bloxcreds} });
    die $session->status_detail if $session->status_code;
    logg 'INFO', "Authenticated to " . $Conf{bloxcreds}{master} . " as " . $Conf{bloxcreds}{username};

    ($dns) = $session->get( object => 'Infoblox::Grid::DNS', name => 'Infoblox' );
    die $session->status_detail if $session->status_code;
    logg 'INFO', "Loaded DNS service object for grid 'Infoblox'";

    @allnsgroups = $session->get( object => 'Infoblox::Grid::DNS::Nsgroup' );
    die $session->status_detail if $session->status_code;
    logg 'INFO', sprintf "Loaded %d NS groups", scalar @allnsgroups;

    ($defgroup) = grep { $_->name eq 'default' } @allnsgroups;
    @bindservers = grep { $_->stealth eq 'true' } @{ $defgroup->secondaries };
    die $session->status_detail if $session->status_code;
    logg 'INFO', sprintf "NS group 'default' has %d anycast stealth secondaries", scalar @bindservers;
}

#####################################################################
## Check whether named.conf stored on local disk is still up-to-date
#####################################################################
sub startup_check {
    logg 'INFO', "Doing startup check...";
    my $current;
    my $file = $Conf{local_namedconf_path};
    eval {
        local $/ = undef; ## read whole file as one blob of text
        open(CUR, $file) or die "Cannot open file $file: $!";
        $current = <CUR>;
        close CUR;
        logg 'INFO', "Read in current named.conf from $file";
    };
    if ($@) {
        logg 'ERR', "$@";
    }
    $current =~ s#^\s*//.*\n##mg;  ## remove all comments

    my $latest = build_namedconf();
    my $latest_copy = $latest;
       $latest_copy =~ s#^\s*//.*\n##mg;   ## remove all comments

    if ($current eq $latest_copy) {
        logg 'NOTICE', "Latest named.conf found to be same as current - NOT updating bindservers";
    }
    else {
        logg 'WARN', "Latest named.conf found to be different from current - updating bindservers";
        update_bindservers($latest);
        reload_bindservers();
    }
    logg 'INFO', "...done startup check";
}

#####################################################################
## Run one or more tests (what did you expect?)
#####################################################################
sub run_tests {
    logg 'INFO', 'TEST: Test mode start.';

    ## Either do all tests or just the one specified with -t
    my @testseq = $testing eq 'all' ? @AllTests : ($testing, undef);
    my($tested, $succeeded);

    while (my $test = shift @testseq) {
        my $arg = shift @testseq;  ## there'd better be an even number of items

        unless (exists($Events{$test}) && $Events{$test}->{testgen}) {
            logg 'ERR', "No event $test, or event has no testgen";
            next;
        }
        logg 'INFO', sprintf "DO TEST --> $test %s", printable($arg);
        local $wait = $wait;  ## localize var and also initialize with "global" value

        ## Cause the event to happen on the appliance
        my $gencode;
        $tested++;
        eval {
            $gencode = $Events{$test}->{testgen}->($arg);  ## call event generator routine
        };
        if ($@) {
            logg 'ERR', "$@";
            next;
        }

        ## Check to see what the appliance reports to you
        while (my $line = get_log($wait)) {
            my $evcode = handle_events($line);

            if ($evcode && $evcode eq $gencode) {
                logg 'INFO', "SUCCESS --> $evcode";
                $succeeded++;
                last;
            }
        }
    }
    logg 'INFO', sprintf 'TEST: %d tests performed, %d apparently succeeded.', $tested, $succeeded;
    logg 'INFO', 'TEST: Test mode end.';
}

########################################################################
## Called when SIGHUP signal is received
########################################################################
sub hup_handler {
    my($sig) = @_;
    logg 'ALERT', "Received SIG$sig !";
    logg 'NOTICE', "Re-reading config...";
    if (read_config(1)) {
        logg 'NOTICE', "Re-initializing...";
        initialize(1);
    }
    logg 'INFO', sprintf "Back to watching the log on %s...", $Conf{syslog_path};
}

########################################################################
## Called when SIGUSR1 signal is received
########################################################################
sub usr1_handler {
    my($sig) = @_;
    logg 'ALERT', "Received SIG$sig !";
    logg 'NOTICE', "Updating bindservers...";
    update_bindservers();
    logg 'NOTICE', "Reloading bindservers...";
    reload_bindservers();
}

########################################################################
## Die gracefully
########################################################################
sub terminate {
    my($sig) = @_;
    logg 'ALERT', "Terminating on SIG$sig";
    $logfh->close if ref($logfh) && $logfh->opened;
    exit;
}

########################################################################
## Append messages to ACM's logg, subject to the loglevel
########################################################################
sub logg {
    my $level = shift;
    my $nlevel = $Severity{$level} || int($level);
    if ($nlevel <= $loglevel) {
        my $ts = scalar(localtime());
        printf $logfh "%s %-12s @_\n", $ts, "LOG($level):";
    }
}

########################################################################
## Sorting comparators and misc. utilities
########################################################################
sub by_objname { $a->name cmp $b->name }

sub printable {
    ## Convert nested arrays to printable form
    my $arg = shift;
    ## Sweet! How often do you get to write recursion in real life? :-)
    ref($arg) eq 'ARRAY' ?
        '[' . join(", ", map { printable($_) } @{$arg}) . ']' :
        $arg || '<null>';
}

__END__
=pod

=head1 DESCRIPTION

ACM is a daemon that watches for DNS-related events in the audit log of an Infoblox appliance,
and takes some action depending on what event has occurred. More specifically, its overall mission
is to keep a set of anycast BIND servers (defined inside the appliance) in sync with the state of
the appliance by updating their named.conf files and reloading BIND at appropriate times.

Logfile can be specified as a filesystem path or as STDERR, and, on the command line or in the
configuration file.  Command line options *always* override settings in the config file.
Loglevel can be specified as integer (5) or all-caps name (NOTICE).  (In order to keep the code
clean, it's not possible to choose a loglevel of EMERG or 0, but I don't think you'd ever want
to choose this level anyway.  It is still possible to log at EMERG level.)

=head1 SIGNAL HANDLING

The program will terminate gracefully if it receives any of SIGINT, SIGQUIT, SIGTERM,
SIGTSTP or SIGABRT.

On receipt of SIGUSR1, the program will create a new named.conf file and distribute it
to the anycast bindservers.

On receipt of SIGHUP, the program will reread its configuration file and reinitialize itself.

=head1 RUNNING IN TEST MODE

First, shut down the normal ACM daemon on the dev host, just to avoid any unwanted "collisions".
You ought to be able to run the full test suite using a command line like this:

 /opt/perl/bin/perl /opt/uen/bin/acm.pl -l STDERR -c /opt/uen/etc/acm.conf -t all

You'll normally be running a full suite, because the utility of specifying individual events
to test (detailed below) is limited by the fact that most events require some "state" to work
properly - usually, a certain zone to exist on the appliance already - which it typically
doesn't.

Use the counts listed at the end of the test as a guide, but don't depend on them to accurately
reflect the results. You'll need to refer to the ACM log output (type=NOTICE) to be sure of what
happened. The program's ability to detect a successful test on its own is, in some cases, limited.

NOTE: the side-effect actions which are the meat-and-potatoes of ACM's functionality (updating
named.conf files on remote bindservers and reloading BIND) do not occur in test mode.

=head1 DEVELOPMENT

The Infoblox appliance events, recorded in the audit log, which are recognized
and acted upon by this program are stored in the hash %Events, which is defined in
the file acm_events.pl. Each entry in the hash is keyed with the event name (local
to this program), and is comprised of a subhash containing exactly three fields:

 match - a regex used to "scrape" audit log lines in order to recognize the
    event. This can also be a list of alternate regexes, which will be
    tried in the order given in the list (e.g. see modify_allowxfer).

 handler - a callback routine (a closure) which is called when an event match
    is found, and which implements ACM's response to the event.

    Input parameters: The (ordered) captured substring tokens from 'match'.
       Tokens appear at the same index in the parameter list as their capture
       variable (i.e. regex capture $1 becomes parameter $_[1], etc).
    Returns: (optionally) a "code" string which ACM in test mode will attempt
       to match against one returned by testgen() to detect a successful test.

 testgen - a callback (closure) which causes an instance of the event to
    occur, for testing purposes. (If the event cannot be caused via API calls,
    it may be necessary to depend on a human to do it, e.g. see how this is
    done by the restore_zone event.)

    Input parameters: Just one (see below for details).
    Returns: (optionally) a "code" string which ACM in test mode will attempt
       to match against one returned by handler() to detect a successful test.

The matching process stops when an event match is found. Consequently, since the events
are not specified to be checked in a given order (the order is random), matches MUST be written
so that no two regexes will ever match the same log line! (unless they are members of an
alternate-set within the same event).

If you add new events to be handled, be sure to include them in @AllTests,
the default testing "script".

Perl arcana: note that variables from the main code whose values need to be accessed
within the handler() and testgen() routines need to be defined in acm.pl as storage class
"our" rather than "my" (c.f. $session, $defgroup).

=head2 *** TEST DEVELOPMENT ***

A testgen() callback MUST be written to accept only a single parameter. If the parameter
is a simple scalar value, it can be anything, as determined by the needs of the routine.
If multiple arguments need to be passed into a testgen() routine, they must be passed as
a list reference (ARRAY "object", if you will).

Testgen routines are responsible for internally defining their own default parameter
values. This is necessary to handle the case in which a single event (foo) is tested by
calling acm.pl with "-t foo", because parameters as Perl data objects cannot be satisfactorily
rendered on the shell command line. Default parameter(s) are to be used when the argument
passed in is empty or 'undef'.

The program predefines (for convenience) a zone name for testing purposes, which includes
the process ID number of the ACM process, so that consecutive tests do not interfere with
each other. This name is stored in the variable $testzone, and is available to be used as
a default parameter.

Testgen routines may override (only for their own event) the default timeout value
which determines how long ACM in test mode will wait for a log message to appear before
giving up. This value is in the variable $wait and is normally 8 seconds. For an example
of how this can be used, see the restore_zone event. This timeout value is irrelevant
to ACM in normal running mode.

The default "testing script" (aka full suite), which is run when the option "-t all" is given,
is defined by the @AllTests list variable in the acm_events.pl file.  It is a list of even length,
in which even-numbered members (starting from zero) are the names of events to be tested, and
the following odd-numbered members are the respective arguments to the event names.

=head1 AUTHOR

David J. Iannucci <dji@uen.org>

=head1 VERSION

 $Id: acm.pl,v 1.30 2011/06/28 22:14:32 dji Exp $

=cut
