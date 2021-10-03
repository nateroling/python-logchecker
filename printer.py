import sys
from process import Printer, run
from process import program, message, host, severity, facility

printer = Printer()
printer.discard(
    # Ignore last message repeated junk
    (host == "last") & (message.match("repeated \d times")),

    # Ignore all VPN messages from both routers.
    (host == ["dbq-router", "hc-router"]) & (program == "VPN"),

    # Ignore network failure messages.
    (host == ["dbq-router", "hc-router"]) & (message.match(
        "Log:  NSD FAIL WAN\[1\]",
        "Log:  NSD SUCCESS WAN\[1\]")),

    # Ignore VPN Logins/Logouts
    (host == "dbq-router") & (message.match(".* log in PPTP Server\.")),
    (host == "dbq-router") & (message.match(".* log out PPTP Server\.")),

    # Ignore some Puppet log messages.
    (program == "puppet-master") & (severity == "notice") & message.match(
        "Compiled catalog for ",
        "Caught TERM; calling stop",
        "Reopening log files",
        "Starting Puppet master version "),
    (program == "puppet-agent") & message.match(
        "Finished catalog run ",
        "Caught TERM; calling stop",
        "Reopening log files",
        "Starting Puppet client version"),

    # Why are debug messages even being logged?
    (program == "imapd-ssl") & (severity == "debug"),

    # Maybe we do want to know about some of these?
    (program == "exim") & (severity == "notice"),

    # Ignore INFO messages from some programs.
    (program == [
        "FaxGetty", "rsyslogd", "CRON", "imapd-ssl", "exim", "kernel",
        "smartd", "nagios3", "spamd"]) & (severity == "info"),

    # Ignore INFO messages from some facilities.
    (facility == ["auth", "authpriv", "cron"]) & (severity == "info"),

    # Ignore successful sudo commands.
    (program == "sudo") & message.match(".*TTY=.*PWD=.*USER=.*COMMAND="),

    # Ignore cron-apt notices.
    (program == "cron-apt") & (severity == "notice"),

    # Ignore epmd running message.
    (program == "epmd") & message.match("epmd: epmd running - daemon = 1"),

    # Ignore some apcupsd messages.
    (program == "apcupsd") & message.match(
        "Power failure\.",
        "Power is back\. UPS running on mains.",
        "UPS Self Test switch to battery.",
        "UPS Self Test completed: Not supported"),

    # Ignore ioctl messages from Debian bug 665850
    (facility == "kern") & (severity == "warning") & message.match(
        "\[[0-9]+.[0-9]+\] lvcreate: sending ioctl 1261 to a partition!"),

    # Ignore mysql slave messages, nagios watches this now.
    (program == "mysqld") & message.contains(
        "[Note] Slave I/O thread: Failed reading log event, reconnecting to retry",
        "[ERROR] Slave I/O: error reconnecting to master",
        "[Note] Slave: connected to master"),

    # Ignore mysql warnings about transactions. I need to fix this eventually,
    # but not right now.
    (program == "mysqld") & message.contains(
        "Statement is unsafe because it accesses a non-transactional table after accessing a transactional table within the same transaction"),

    # Ignore spamd restarting
    (program == "spamd.pid") & message.match(
        "spamd: restarting using '/usr/sbin/spamd --create-prefs "\
        "--max-children 5 --helper-home-dir -d --pidfile=/var/run/spamd.pid'"),

    (program == "famd") & message.match(
        "stat on \".*courier\.lock\" failed: No such file or directory"),

    # Ignore ext3_orphan_cleanup
    (facility == "kern") & (severity == "debug") & message.contains(
            "ext3_orphan_cleanup: deleting unreferenced inode "),

    # Ignore 1 unreadable sector on sdb
    (program == "smartd") & message.match(
        "Device: /dev/sdb [SAT], 1 Currently unreadable (pending) sectors")


    )

if __name__ == "__main__":
    run(printer)
    sys.exit(0)

