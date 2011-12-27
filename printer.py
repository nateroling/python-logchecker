import sys
from process import Printer, run
from process import program, message, host, severity, facility

printer = Printer()
printer.discard(
    # DBQ Router log format is retarded, fields don't match.
    # Thankfully it will probably blow a cap soon, like HC.
    # Ignore all VPN messages from both routers.
    (program == "dbq-router") & (message.match("SYSLOG_NK-\(VPN Log\)")),
    (host == "hc-router") & (program == "VPN"),

    # Ignore some Puppet log messages.
    (program == "puppet-agent") & message.match("Finished catalog run "),
    (program == "puppet-master") & (severity == "notice") & message.match("Compiled catalog for "),

    # Why are debug messages even being logged?
    (program == "imapd-ssl") & (severity == "debug"),

    # Maybe we do want to know about some of these?
    (program == "exim") & (severity == "notice"),

    # Ignore INFO messages from some programs.
    (program == ["FaxGetty", "rsyslogd", "CRON", "imapd-ssl", "exim",
                 "kernel", "smartd"]) & (severity == "info"),

    # Ignore INFO messages from some facilities.
    (facility == ["auth", "authpriv", "cron"]) & (severity == "info"),

    # Ignore successful sudo commands.
    (program == "sudo") & message.match(".*TTY=.*PWD=.*USER=.*COMMAND="),

    # Ignore cron-apt notices.
    (program == "cron-apt") & (severity == "notice"),

    # Ignore epmd running message.
    (program == "epmd") & message.match("epmd: epmd running - daemon = 1"))

if __name__ == "__main__":
    run(printer)
    sys.exit(0)

