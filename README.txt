****** DNS tools

The production host for these programs is *****.uen.net; development is on *****.uen.org.
Structures are identical on the two hosts.  The user "***" is the owner of files and generally
used for maintenance activities.

*** ACM - The Anycast Manager

ACM is made up of 4 files:

    Located in /opt/uen/bin:
        1. acm.pl - the main code

    Located in /opt/uen/etc:
        2. acm_events.pl - definition of events and tests
        3. acm.conf - configuration file
        4. header.txt - static header boilerplate for named.conf files

To release new code, simply copy new files into the indicated locations (acm.conf is not revision-
controlled and can be edited in place).  The actual execution of ACM is handled by the Solaris
svcadm(?) system, which is managed by the UA group.

When configuring ACM, be very careful to set the Infoblox master to the correct host appliance!
You should not need to touch the sshparams.... or probably anything else for that matter.
 
To restart the acm daemon, do "sudo svcadm restart acm". This can be done on sidekick while
logged in as nsmaint (you'll need the latter's password, of course).

ACM writes its own log in /opt/uen/logs/acm.log


*** Monac - The Anycast Monitor

The monitor is divided into two parts that communicate via information stored in a shared
file on the filesystem:

    * monacd.pl - the daemon that queries status information from the Bind servers
    * monac.cgi - the web interface that displays status information

These two share a config file which is expected to be located in /opt/uen/etc/monac.conf.

As Monac is still under development, no final decisions have been made at the time of writing
as to where programs and associated files will be installed, however the daemon will probably
go in /opt/uen/bin and managed by svcadm, along with ACM. The web interface will go wherever
CGI programs need to go for the web server (currently for testing it is in /var/apache2/cgi-bin).

The development web interface can be accessed at:
   http://*****.uen.org/cgi-bin/monac.cgi

This document will be updated after Monac is released to production.

