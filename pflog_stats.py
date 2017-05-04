#!/bin/env python

"""
Based on idea from https://forums.freebsd.org/threads/3592/


use as in-line parser for tcpdump:
    tcpdump -enr pflog.0 | python parse_pflog.py
"""

import re,sys
import json
import argparse
import socket



# 00:00:01.937933 rule 5.intra_services.20/0(match): pass in on vr2: 192.168.3.128.49144 > 192.168.0.1.53: 53364+[|domain]
# 00:39:55.221738 rule 4.icmp.2/0(match): pass in on vr2: 192.168.3.107 > 192.168.3.1: ICMP echo request, id 11778, seq 1, length 64

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

def parse_log(file_object):
    x=re.compile(r'rule (?P<rule>\S+)\: (?P<action>pass|block) (?P<direction>in|out) on (?P<interface>\w+)\: (?P<source_host>\d+\.\d+\.\d+\.\d+)(?:\.(?P<source_port>\d+))? > (?P<destination_host>\d+\.\d+\.\d+\.\d+)(?:\.(?P<destination_port>\d+))?\:')
    for s in file_object:
      m=x.search(s)
      log={}
      try:
        for block in ('rule','action','direction','interface','source_host','source_port','destination_host','destination_port'):
            log[block]=m.group(block)
      except:
        print "!!!", s
        continue
      yield log

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--regexp", action="store_true", default=False, help="Criterion provided in filters shall be treated as regexp")
    parser.add_argument("--filter-src", help="print stats only for sources matching criteria")
    parser.add_argument("--filter-dst", help="print stats only for destinations matching criteria")
    parser.add_argument("--resolve-dst", action="store_true", default=False, 
            help="resolve destination IPs")
    parser.add_argument("--resolve-src", action="store_true", default=False, 
            help="resolve source IPs")
    args=parser.parse_args()

    filter_params={}
    if args.filter_src:
        filter_params['source_host']=args.filter_src

    if args.filter_dst:
        filter_params['destination_host']=args.filter_dst

    if args.regexp:
        log_filter=ReFilter(**filter_params)
    else:
        log_filter=Filter(**filter_params)
    pre_stats={}
    for log in log_filter(parse_log(sys.stdin)):
      try:
        source=log['source_host']
        destination=log['destination_host']
        # print log
        if not pre_stats.has_key(source):
            pre_stats[source]={}
        if not pre_stats[source].has_key(destination):
            pre_stats[source][destination]=1
        else:
            pre_stats[source][destination]+=1
        # print m.groups()
      except Exception, e:
          print e

    stats={}
    for source_ip in pre_stats:
        if args.resolve_src:
            try:
                source=socket.gethostbyaddr(source_ip)[0]
            except:
                source=source_ip
        else:
            source=source_ip
        stats[source]={}
        for destination_ip in pre_stats[source_ip]:
            if args.resolve_dst:
                try:
                    destination=socket.gethostbyaddr(destination_ip)[0]
                except:
                    destination=destination_ip
            else:
                destination=destination_ip
            stats[source][destination]=pre_stats[source_ip][destination_ip]

    print json.dumps(stats,indent=2)

if __name__ == '__main__':
    main()
