#!/bin/env python

"""
Based on idea from https://forums.freebsd.org/threads/3592/


use as in-line parser for tcpdump:
    tcpdump -enr pflog.0 | python pflog_stats.py
"""

import re,sys
import json
import argparse
import socket

# 00:00:01.937933 rule 5.intra_services.20/0(match): pass in on vr2: 192.168.3.128.49144 > 192.168.0.1.53: 53364+[|domain]
# 00:39:55.221738 rule 4.icmp.2/0(match): pass in on vr2: 192.168.3.107 > 192.168.3.1: ICMP echo request, id 11778, seq 1, length 64

LOG_ELEMENTS   =('timestamp','rule','action','direction','interface','source_host','source_port','destination_host','destination_port','details')
FILTER_OPTIONS =('timestamp','rule','action','direction','interface','source-host','source-port','destination-host','destination-port','details')


class Filter:
    """ Include only selected records
    """
    def __init__(self, **kwargs):
        """ passed params are keys from log hash - used to apply filtering
        """
        self.filters={}
        for key in kwargs:
            self.filters[key]=kwargs[key]

    def __call__(self,log_iterator):
        for log in log_iterator:
            passed=True
            for f in self.filters:
                if self.filters[f] != log[f]:
                    passed=False
                    break
            if passed:
                yield log

class ReFilter:
    """ Include only selected records matching the RE
    """
    def __init__(self, **kwargs):
        """ passed params are keys from log hash - used to apply filtering
        """
        self.filters={}
        for key in kwargs:
            self.filters[key]=re.compile(kwargs[key])

    def __call__(self,log_iterator):
        for log in log_iterator:
            passed=True
            for f in self.filters:
                if not self.filters[f].search(log[f]):
                    passed=False
                    break
            if passed:
                yield log

class PFParser(object):
    def __init__(self, filter_obj):
        self.filter=filter_obj
        # self.input=input_stream
        # self.resolve_src=False
        # self.resolve_dst=False
        self.dns_cache={}

    def parse(self,input_stream,resolve_src,resolve_dst):
        pass
    
    def _resolve_ip(self,ip_addr):
        try:
            if ip_addr not in self.dns_cache:
                self.dns_cache[ip_addr]=socket.gethostbyaddr(ip_addr)[0]
        except Exception as ex:
            # print(ip_addr)
            # print(ex)
            self.dns_cache[ip_addr]=ip_addr
        return self.dns_cache[ip_addr]

class StatsParser(PFParser):
    def __init__(self, filter_obj):
        PFParser.__init__(self, filter_obj)
    
    def parse(self,input_stream,resolve_src,resolve_dst,resolve2field=False):
        pre_stats={}
        for log in self.filter(parse_log(input_stream)):
          try:
            source=log['source_host']
            destination=log['destination_host']
            # print log
            if source not in pre_stats:
                pre_stats[source]={}
            if destination not in pre_stats[source]:
                pre_stats[source][destination]=1
            else:
                pre_stats[source][destination]+=1
            # print m.groups()
          except Exception as e:
              print(str(e))

        stats={}
        for source_ip in pre_stats:
            if resolve_src:
                source=self._resolve_ip(source_ip)
            else:
                source=source_ip
            stats[source]={}
            for destination_ip in pre_stats[source_ip]:
                if resolve_dst:
                    destination=self._resolve_ip(destination_ip)
                else:
                    destination=destination_ip
                stats[source][destination]=pre_stats[source_ip][destination_ip]
        return stats

class LineParser(PFParser):
    def __init__(self, filter_obj):
        PFParser.__init__(self, filter_obj)
        self.field_filter=LOG_ELEMENTS
    
    def setFieldFilter(self,field_filter):
        self.field_filter=field_filter
    
    def parse(self,input_stream,resolve_src,resolve_dst,resolve2field=False):
        stats=[]
        for log in self.filter(parse_log(input_stream)):
            entry={}
            for f in self.field_filter:
                log_field=log[f]
                resolved_field=None
                if f == 'source_host':
                    if resolve_src and not resolve2field:
                        log_field=self._resolve_ip(log[f])
                    elif resolve_src and resolve2field:
                        resolved_field='src'
                        resolved=self._resolve_ip(log[f])
                elif f == 'destination_host':
                    if resolve_dst and not resolve2field:
                        log_field=self._resolve_ip(log[f])
                    elif resolve_dst and resolve2field:
                        resolved_field='dst'
                        resolved=self._resolve_ip(log[f])
                if resolve2field and resolved_field:
                    entry['resolved_'+resolved_field]=resolved
                entry[f]=log_field
            stats.append(entry)
        return stats

def parse_log(file_object):
    """
    produce an iterator returning dictionary equivalent of log entry
    """
    # 21:27:20.200343 rule 1.wifi.0/0(match): pass in on vr2: 192.168.3.214.33735 > 208.67.222.123.53: 39699+ [1au] AAAA? piazza.com. (39)

    x=re.compile(r'(?P<timestamp>[\d\:\.]+) rule (?P<rule>\S+)\: (?P<action>pass|block|\S+) (?P<direction>in|out) on (?P<interface>\w+)\: (?P<source_host>\d+\.\d+\.\d+\.\d+)(?:\.(?P<source_port>\d+))? > (?P<destination_host>\d+\.\d+\.\d+\.\d+)(?:\.(?P<destination_port>\d+))?\: (?P<details>.*)')
    for s in file_object:
      m=x.search(s)
      log={}
      try:
        for block in LOG_ELEMENTS:
            log[block]=m.group(block)
      except:
        print("!!!{}".format(s))
        continue
      yield log

def main():
    parser=argparse.ArgumentParser(description='Parse pflog output produced by "tcpdump -ne"')
    parser.add_argument("--regexp", action="store_true", default=False, help="Criterion provided in filters shall be treated as regexp")
    # filter_arg_dict=dict(zip(LOG_ELEMENTS,FILTER_OPTIONS))
    for e,o in zip(LOG_ELEMENTS,FILTER_OPTIONS):
        parser.add_argument("--select-"+o, dest=e, default=None, help="select "+o+" matching lines")
    # parser.add_argument("--filter-src", help="print stats only for sources matching criteria")
    # parser.add_argument("--filter-dst", help="print stats only for destinations matching criteria")
    parser.add_argument('--resolve-to-field', action="store_true", default=False)
    parser.add_argument("--resolve-dst", action="store_true", default=False, 
            help="resolve destination IPs")
    parser.add_argument("--resolve-src", action="store_true", default=False, 
            help="resolve source IPs")
    parser.add_argument("--parser", choices=['stats','lines'], default='stats')
    parser.add_argument("--output-field", choices=LOG_ELEMENTS, action="append", dest='output_fields')
    parser.add_argument("--format", choices=['compact', 'pretty', 'log'], default='pretty')
    args=parser.parse_args()

    filter_params={}
    args_dict=vars(args)
    for e,o in zip(LOG_ELEMENTS,FILTER_OPTIONS):
        if e in args_dict:
            if not (args_dict[e] is None):
                filter_params[e]=args_dict[e]
    # print "Selected: ", filter_params
    # print "Fields: ", args.output_fields

    if args.regexp:
        log_filter=ReFilter(**filter_params)
    else:
        log_filter=Filter(**filter_params)

    if args.parser=='stats':
        pfparser=StatsParser(log_filter)
    elif args.parser=='lines':
        pfparser=LineParser(log_filter)
        if args.output_fields:
            pfparser.setFieldFilter(args.output_fields)
    stats=pfparser.parse(sys.stdin, args.resolve_src, args.resolve_dst,args.resolve_to_field)
    output={'selected': filter_params, 'fields': args.output_fields, 'stats': stats}
    if args.format=='compact':
        print(json.dumps(output))
    elif args.format=='pretty':
        print(json.dumps(output,indent=2))
    elif args.format=='log':
        for l in stats:
            print(json.dumps(l))


if __name__ == '__main__':
    main()
