import sys
import process
from process import Runner, Counter

counter= Counter("exim notices", print_other=True)
counter.require((process.program == "exim") & (process.severity == "notice"))

# Count certain exim notices.
counter.count("unroutable address", process.message.match(".*Unrouteable address$"))
counter.count("relay not permitted", process.message.match(".*relay not permitted$"))
counter.count("syntactically invalid", process.message.contains("syntactically invalid argument"))
counter.count("synchronization error", process.message.match("SMTP protocol synchronization error"))

runner = Runner()
runner.add(counter)

def main():
    runner.run(sys.stdin)

if __name__ == "__main__":
    main()
    sys.exit(0)

