import sys
import process
from process import Counter, run
from process import message

counter= Counter("exim notices")
counter.require((process.program == "exim") & (process.severity == "notice"))

# Count certain exim notices.
counter.count("unroutable address", message.match(".*Unrouteable address$"))
counter.count("relay not permitted", message.match(".*relay not permitted$"))
counter.count("syntactically invalid", message.contains("syntactically invalid argument"))
counter.count("synchronization error", message.match("SMTP protocol synchronization error"))

if __name__ == "__main__":
    run(counter)
    sys.exit(0)

