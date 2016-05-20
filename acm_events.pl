=pod

=head1 NAME

acm_events.pl - Definition of events handled by ACM, and testing resources

=cut

sub logg;

### The shared stuff that all lines will match
my $preamble = qr/.*(20\d\d-\d\d-\d\d) (\d\d:\d\d:\d\d).*\[([-.\w]+)\]/o;
### captures ->      $1 (date)          $2 (time)           $3 (user)

my $testzone = "acm-test-$$.net";  ## zone name includes PID of current acm.pl process

%Events = (
    create_zone => {
        match => qr/^$preamble: Created AuthZone (\S+) /,
        ### captures ->                           $4 (zone)
        handler => sub {
            return unless $_[4];  ## not a zone event after all
            logg 'NOTICE', "Zone change: $_[4], Created by $_[3]";
            update_bindservers();
            return "ADD $_[4]";
        },
        testgen => sub {
            my $arg = shift || $testzone;
            my $zone = new Infoblox::DNS::Zone ( name => $arg );
            $session->add($zone) or die $session->status_detail;
            return "ADD $arg";
        }
    },
    delete_zone => {
        match => qr/^$preamble: Deleted AuthZone (\S+) /,
        ### captures ->                           $4 (zone)
        handler => sub {
            return unless $_[4];  ## not a zone event after all
            logg 'NOTICE', "Zone change: $_[4], Deleted by $_[3]";
            update_bindservers();
            return "DEL $_[4]";
        },
        testgen => sub {
            my $arg = shift || $testzone;
            my $zone = $session->get( object => 'Infoblox::DNS::Zone', name => $arg ) or
                die "Fatal: Cannot find zone $arg";
            $session->remove($zone) or die $session->status_detail;
            return "DEL $arg";
        }
    },
    modify_allowxfer => {
        match => [
            qr/^$preamble: Modified AuthZone (\S+).*Changed .*(use_zone_transfer_setting:(True|False)->(True|False))/,
            qr/^$preamble: Modified AuthZone (\S+).*Changed .*(allow_transfer):/,
            ### captures ->                   $4 (zone)        $5                         $6            $7
        ],
        handler => sub {
            return unless $_[4];  ## not a zone event after all
            logg 'NOTICE', "Zone change: $_[4], Modified ($_[5]) by $_[3]";
            update_bindservers();
            return sprintf("ALLOWXFER %s %s", $_[4], getaxcode($_[5]));
        },
        testgen => sub {
            my $arg = shift || [$testzone, undef];
            my $zone = $session->get( object => 'Infoblox::DNS::Zone', name => $arg->[0] ) or
                die "Fatal: Cannot find zone " . $arg->[0];
            $zone->allow_transfer($arg->[1]);
            $session->modify($zone) or die $session->status_detail;
            return sprintf "ALLOWXFER %s %s", $arg->[0], getaxcode($arg->[1]);
        }
    },
    restore_zone => {
        match => qr/^$preamble: Called - Restore .*Name=(\S+) ObjectType=AuthZone/,
        ### captures ->                                  $4 (zone)
        handler => sub {
            return unless $_[4];  ## not a zone event after all
            logg 'NOTICE', "Zone change: $_[4], Restored by $_[3]";
            update_bindservers();
            return "RESTORE $_[4]";
        },
        testgen => sub {
            my $arg = shift || $testzone;
            $wait = 60;   ## change timeout value - only for this test
            logg 'ALERT', "***ATTN***: You must restore zone $arg manually through the web GUI. " .
                          "You now have $wait seconds to do that.";
            return "RESTORE $arg";
        }
    },
    restart_services => {
        match => qr/^$preamble: Called - (Grid|Member)RestartServices/,
        handler => sub {
            logg 'NOTICE', "Restart of services by $_[3]";
            reload_bindservers();
            return "RESTART SERVICES";
        },
        testgen => sub {
            my $arg = shift || $defgroup->primary->ipv4addr;
            $session->restart( force_restart => 'true' ) or die $session->status_detail;
            return "RESTART SERVICES";
        }
    }
);

## The full test suite that runs for -t all

@AllTests = (
    'create_zone', $testzone,
    'modify_allowxfer', [$testzone, []],
    'modify_allowxfer', [$testzone, ['192.168.0.0/24']],
    'modify_allowxfer', [$testzone, undef],
    'delete_zone', $testzone,
    'restore_zone', $testzone,
    'delete_zone', $testzone,   ## back to the recycle bin, to keep things clean
    'restart_services', undef
);

### From here down: utility routines called only _within this file_

########################################################################
## Convert allow_transfer() argument or log token into a unique code
########################################################################
sub getaxcode {
    my $arg = shift;

    if (!defined($arg)) {
        'GLOBAL';
    }
    elsif (ref($arg) eq 'ARRAY') {
        'BYZONE';
    }
    elsif ($arg =~ /True->False/i) {
        'GLOBAL';
    }
    else {
        'BYZONE';
    }
}

1;
__END__
=pod

=head1 AUTHOR

David J. Iannucci <dji@uen.org>

=head1 VERSION

 $Id: acm_events.pl,v 1.4 2011/06/03 22:21:30 dji Exp $

=cut
