import sys
from pyparsing import Word, nums, alphas, Regex, Suppress, Optional,\
        ParseException
from dateutil.parser import parse as parse_date
import re
from collections import defaultdict

# TODO
# Customizable message printing formats


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

class Processor:

    def process(self, msg):
        pass

    def parse_failed(self, msg):
        pass

    def postprocess(self):
        pass


class Printer(Processor):

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
            print msg.raw

    def parse_failed(self, rawmsg):
        print "FAILED TO PARSE: %s" % rawmsg


class Counter(Processor):

    def __init__(self, title="Counted", print_other=True, print_zero=False):
        self._title = title
        self._print_other = print_other
        self._print_zero = print_zero
        self._preconditions = []
        self._rules = []
        self._counts = defaultdict(int)
        self._other = 0
        self._other_msgs = []
        self.output = []

    def count(self, name, *rules, **kwargs):
        for rule in rules:
            self._rules.append((name, rule, kwargs.get('threshold')))

    def require(self, *rules):
        for rule in rules:
            self._preconditions.append(rule)

    def process(self, msg):
        for rule in self._preconditions:
            if not rule(msg):
                return False
        for name, rule, threshold in self._rules:
            if rule(msg):
                self._counts[name] += 1
                return True
        self._other += 1
        self._other_msgs.append(msg)
        return False

    def _matched_any(self):
        return any(self._counts.values()) or self._other

    def _output_count(self, name, value, threshold=None):
        if threshold and value <= threshold:
            return
        if value > 0 or self._print_zero:
            self.output.append("{1:>5} {0}".format(name, value))

    def postprocess(self):
        for name, rule, threshold in self._rules:
            self._output_count(name, self._counts[name], threshold)
        if self._print_other:
            self._output_count("others", self._other)
            for msg in self._other_msgs:
                self.output.append("      %s %s %s" % (msg.host, msg.program, msg.message))
        if self.output:
            print(self._title)
            print("-" * len(self._title))
            for line in self.output:
                print line
            print("")


class Runner:
    """
    Container for a number of log processors.
    """
    def __init__(self):
        self.processors = []

    def add(self, processor):
        self.processors.append(processor)

    def run(self, input):
        for m in input:
            if m == "\n":
                continue
            try:
                raw = m.strip()
                msg = parser.parseString(raw)
                msg['raw'] = raw
                for p in self.processors:
                    p.process(msg)
            except ParseException:
                for p in self.processors:
                    p.parse_failed(m.strip())

        for p in self.processors:
            p.postprocess()


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

    def __invert__(self):
        def func(value):
            return not self._func(value)
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
_program = Optional(Word(alphas + nums + "_-."))
_pid = Optional(Word(nums + "-"))
_s = Suppress

parser = (_datetime("time") + _hostname("host") + _facility("facility") +
          _s(".") + _severity("severity") + _program("program") + _s("[") +
          _pid("pid") + _s("]:") + Regex(r".*")("message"))


severity = Field("severity")
facility = Field("facility")
program = Field("program")
message = Field("message")
host = Field("host")

def run(*processors):
    runner = Runner()
    for x in processors:
        runner.add(x)
    runner.run(sys.stdin)

