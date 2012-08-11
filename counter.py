import sys
import process
from process import Counter, run
from process import message

exim_counter = Counter("exim notices")
exim_counter.require((process.program == "exim") & (process.severity == "notice"))

# Count certain exim notices.
exim_counter.count(
    "unroutable address",
    message.match(".*Unrouteable address$"),
    threshold=5)

exim_counter.count(
    "spam",
    message.match(".*rejected after DATA: Spam score \d+"),
    threshold=200)

exim_counter.count(
    "relay not permitted",
    message.match(".*relay not permitted$"),
    threshold=5)

exim_counter.count(
    "syntactically invalid - no argument",
    message.contains("syntactically invalid argument") &
    message.contains("no argument given"),
    threshold=100)

exim_counter.count(
    "syntactically invalid",
    message.contains("syntactically invalid argument"),
    threshold=5)

exim_counter.count(
    "synchronization error",
    message.match("SMTP protocol synchronization error"),
    threshold=5)


spamd_counter = Counter("spamd")
spamd_counter.require(process.program == "spamd.pid")

# Count spamd restarts.
spamd_counter.count("spamd restart", message.match(
    "spamd: restarting using '/usr/sbin/spamd --create-prefs "\
    "--max-children 5 --helper-home-dir -d --pidfile=/var/run/spamd.pid'"),
    threshold=1)

if __name__ == "__main__":
    run(exim_counter, spamd_counter)
    sys.exit(0)

