from pyparsing import Word, nums, alphas, Regex, Suppress, Optional
from dateutil.parser import parse as parse_date
import re
from collections import defaultdict


class Severity:
    """
    Represents the severity of a log message. Initialize with one of:
        emerg alert crit err warning notice info debug

    Note that Severity objects compare reverse to how numeric severity levels
    work. That is, emerg > alert, and info < err.

    You can compare Severity objects directly to strings:
    Severity("warning") > "notice"
    """

    LEVELS = "emerg alert crit err warning notice info debug".split()

    def __init__(self, value):
        self.value = value
        self.level = Severity.LEVELS.index(value)

    def __cmp__(self, other):
        if not isinstance(other, Severity):
            if isinstance(other, str):
                try:
                    other = Severity(other)
                except ValueError:
                    raise ValueError("{0} is not a valid severity level".format(other))
            else:
                return -1
        if self.level == other.level:
            return 0
        elif self.level < other.level:
            return 1
        else:
            return -1

    def __str__(self):
        return self.value


class Printer:

    def __init__(self):
        self._rules = []

    def discard(self, *rules):
        self._rules.extend(rules)

    def should_discard(self, msg):
        for rule in self._rules:
            if rule(msg):
                return True
        return False

    def process(self, msg):
        if not self.should_discard(msg):
            print msg.host, msg.program, msg.message


class Counter:

    def __init__(self):
        self._rules = []
        self._counts = defaultdict(int)

    def count(self, name, *rules):
        for rule in rules:
            self._rules.append((name, rule))

    def process(self, msg):
        for name, rule in self._rules:
            if rule(msg):
                self._counts[name] += 1
                return True
        return False

    def postprocess(self):
        for name, rule in self._rules:
            print("Counted {1} {0}".format(
                name, self._counts[name]))


class Rule:

    def __init__(self, func):
        self._func = func

    def __call__(self, value):
        return self._func(value)

    def __and__(self, other):
        def func(value):
            return self._func(value) and other._func(value)
        return Rule(func)

    def __or__(self, other):
        def func(value):
            return self._func(value) or other._func(value)
        return Rule(func)

    def __nonzero__(self):
        raise Exception("Can't cast Rule to boolean, did you mean & or |?")


class Field:

    def __init__(self, attr):
        self.attr = attr

    def __lt__(self, other):
        def func(value):
            return getattr(value, self.attr) < other
        return Rule(func)

    def __gt__(self, other):
        def func(value):
            return getattr(value, self.attr) > other
        return Rule(func)

    def __le__(self, other):
        def func(value):
            return getattr(value, self.attr) <= other
        return Rule(func)

    def __ge__(self, other):
        def func(value):
            return getattr(value, self.attr) >= other
        return Rule(func)

    def __eq__(self, other):
        def func(value):
            if isinstance(other, list):
                for o in other:
                    if getattr(value, self.attr) == o:
                        return True
                return False
            else:
                return getattr(value, self.attr) == other
        return Rule(func)

    def __ne__(self, other):
        def func(value):
            return getattr(value, self.attr) != other
        return Rule(func)

    def match(self, *regexes):
        def func(value):
            for regex in regexes:
                if re.match(regex, getattr(value, self.attr)) != None:
                    return True
            return False
        return Rule(func)

    def contains(self, *strings):
        def func(value):
            for string in strings:
                if string in getattr(value, self.attr):
                    return True
            return False
        return Rule(func)


_datetime = Word(nums + "-+T:.").addParseAction(lambda t: parse_date(t[0]))
_hostname = Word(alphas + nums + "-")
_facility = Word(alphas + nums)
_severity = Word(alphas).addParseAction(lambda t: [Severity(x) for x in t])
_program = Optional(Word(alphas + nums + "_-"))
_pid = Word(nums + "-")
_s = Suppress

parser = (_datetime("time") + _hostname("host") + _facility("facility") +
          _s(".") + _severity("severity") + _program("program") + _s("[") +
          _pid("pid") + _s("]: ") + Regex(r".*")("message"))


severity = Field("severity")
facility = Field("facility")
program = Field("program")
message = Field("message")
host = Field("host")

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
    (facility == ["auth", "authpriv", "cron"]) & (severity == "info"))

counter = Counter()
counter.count("hc router messages", (host == "hc-router"))
counter.count("dbq router messages", (program == "dbq-router"))
counter.count("exim notices", (program == "exim") & (severity == "notice"))

def main():
    import sys

    for m in sys.stdin:
        if m == "\n":
            continue
        msg = parser.parseString(m.strip())
        printer.process(msg)
        counter.process(msg)

    counter.postprocess()


if __name__ == "__main__":
    main()

