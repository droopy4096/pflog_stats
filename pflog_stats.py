#!/bin/env python

"""
Based on idea from https://forums.freebsd.org/threads/3592/


use as in-line parser for tcpdump:
    tcpdump -enr pflog.0 | python pflog_stats.py
"""

import re
import sys
import json
import argparse
import socket



# 00:00:01.937933 rule 5.intra_services.20/0(match): pass in on vr2: 192.168.3.128.49144 > 192.168.0.1.53: 53364+[|domain]
# 00:39:55.221738 rule 4.icmp.2/0(match): pass in on vr2: 192.168.3.107 > 192.168.3.1: ICMP echo request, id 11778, seq 1, length 64

LOG_ELEMENTS = ('timestamp', 'rule', 'action', 'direction', 'interface',
                'source_host', 'source_port', 'destination_host', 'destination_port')
FILTER_OPTIONS = ('timestamp', 'rule', 'action', 'direction', 'interface',
                  'source-host', 'source-port', 'destination-host', 'destination-port')


class Filter(object):
    def __init__(self, **kwargs):
        pass
    def __call__(self, log_iterator):
        pass

class StrFilter(Filter):
    """ Include only selected records
    """
    def __init__(self, **kwargs):
        """ passed params are keys from log hash - used to apply filtering
        """
        Filter.__init__(self, **kwargs)
        self.filters = {}
        for key in kwargs:
            self.filters[key] = kwargs[key]

    def __call__(self, log_iterator):
        for log in log_iterator:
            passed = True
            for field in self.filters:
                if self.filters[field] != log[field]:
                    passed = False
                    break
            if passed:
                yield log

class ReFilter(Filter):
    """ Include only selected records matching the RE
    """
    def __init__(self, **kwargs):
        """ passed params are keys from log hash - used to apply filtering
        """
        Filter.__init__(self, **kwargs)
        self.filters = {}
        for key in kwargs:
            self.filters[key] = re.compile(kwargs[key])

    def __call__(self, log_iterator):
        for log in log_iterator:
            passed = True
            for field in self.filters:
                if not self.filters[field].search(log[field]):
                    passed = False
                    break
            if passed:
                yield log

class PFParser(object):
    def __init__(self, filter_obj):
        self.filter = filter_obj
        # self.input=input_stream
        # self.resolve_src=False
        # self.resolve_dst=False
        self.dns_cache = {}

    def parse(self, input_stream, resolve_src, resolve_dst):
        """Abstract method
        """
        pass

    def _resolve_ip(self, ip_addr):
        try:
            if not self.dns_cache.has_key(ip_addr):
                self.dns_cache[ip_addr] = socket.gethostbyaddr(ip_addr)[0]
        except Exception:
            self.dns_cache[ip_addr] = ip_addr
        return self.dns_cache[ip_addr]

class StatsParser(PFParser):
    """Parse logs into stats package
    """
    def __init__(self, filter_obj):
        PFParser.__init__(self, filter_obj)

    def parse(self, input_stream, resolve_src, resolve_dst):
        """ Parse logs
        """
        pre_stats = {}
        for log in self.filter(parse_log(input_stream)):
            try:
                source = log['source_host']
                destination = log['destination_host']
                # print log
                if not pre_stats.has_key(source):
                    pre_stats[source] = {}
                if not pre_stats[source].has_key(destination):
                    pre_stats[source][destination] = 1
                else:
                    pre_stats[source][destination] += 1
                # print m.groups()
            except Exception, exception_caught:
                print exception_caught

        stats = {}
        for source_ip in pre_stats:
            if resolve_src:
                source = self._resolve_ip(source_ip)
            else:
                source = source_ip
            stats[source] = {}
            for destination_ip in pre_stats[source_ip]:
                if resolve_dst:
                    destination = self._resolve_ip(destination_ip)
                else:
                    destination = destination_ip
                stats[source][destination] = pre_stats[source_ip][destination_ip]
        return stats

class LineParser(PFParser):
    """ parse log entries into lines package
    """
    def __init__(self, filter_obj):
        PFParser.__init__(self, filter_obj)
        self.field_filter = LOG_ELEMENTS

    def set_field_filter(self, field_filter):
        """ Set field filter
        """
        self.field_filter = field_filter

    def parse(self, input_stream, resolve_src, resolve_dst):
        stats = []
        for log in self.filter(parse_log(input_stream)):
            entry = {}
            for field in self.field_filter:
                log_field = log[field]
                if field == 'source_host':
                    if resolve_src:
                        log_field = self._resolve_ip(log[field])
                elif field == 'destination_host':
                    if resolve_dst:
                        log_field = self._resolve_ip(log[field])

                entry[field] = log_field
            stats.append(entry)
        return stats

def parse_log(file_object):
    """
    produce an iterator returning dictionary equivalent of log entry
    """
    log_extractor = re.compile(r'(?P<timestamp>[\d\:\.]+) rule (?P<rule>\S+)\: (?P<action>pass|block) (?P<direction>in|out) on (?P<interface>\w+)\: (?P<source_host>\d+\.\d+\.\d+\.\d+)(?:\.(?P<source_port>\d+))? > (?P<destination_host>\d+\.\d+\.\d+\.\d+)(?:\.(?P<destination_port>\d+))?\:')
    for log_line in file_object:
        matches = log_extractor.search(log_line)
        log = {}
        try:
            for block in LOG_ELEMENTS:
                log[block] = matches.group(block)
        except:
            print "!!!", log_line
            continue
        yield log

def main():
    """ main entry point into the module for CLI use"""
    parser = argparse.ArgumentParser(description='Parse pflog output produced by "tcpdump -ne"')
    parser.add_argument("--regexp", action="store_true", default=False,
                        help="Criterion provided in filters shall be treated as regexp")
    # filter_arg_dict=dict(zip(LOG_ELEMENTS,FILTER_OPTIONS))
    for element, option in zip(LOG_ELEMENTS, FILTER_OPTIONS):
        parser.add_argument("--select-"+option, dest=element, default=None,
                            help="select "+option+" matching lines")
    parser.add_argument("--resolve-dst", action="store_true", default=False,
                        help="resolve destination IPs")
    parser.add_argument("--resolve-src", action="store_true", default=False,
                        help="resolve source IPs")
    parser.add_argument("--parser", choices=['stats', 'lines'], default='stats')
    parser.add_argument("--output-field", choices=LOG_ELEMENTS, action="append",
                        dest='output_fields')
    parser.add_argument("--format", choices=['compact', 'pretty'], default='pretty')
    args = parser.parse_args()

    filter_params = {}
    args_dict = vars(args)
    for element in LOG_ELEMENTS:
        if args_dict.has_key(element):
            if not args_dict[element] is None:
                filter_params[element] = args_dict[element]
    print "Selected: ", filter_params
    print "Fields: ", args.output_fields

    if args.regexp:
        log_filter = ReFilter(**filter_params)
    else:
        log_filter = StrFilter(**filter_params)

    if args.parser == 'stats':
        pfparser = StatsParser(log_filter)
    elif args.parser == 'lines':
        pfparser = LineParser(log_filter)
        if args.output_fields:
            pfparser.set_field_filter(args.output_fields)
    stats = pfparser.parse(sys.stdin, args.resolve_src, args.resolve_dst)
    if args.format == 'compact':
        print json.dumps(stats)
    elif args.format == 'pretty':
        print json.dumps(stats, indent=2)

if __name__ == '__main__':
    main()
