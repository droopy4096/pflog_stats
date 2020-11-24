#!/bin/env python

import re
import sys
import json

# 1606161614.421928 IP 192.168.3.214.50284 > 208.67.222.123.53: 62398+ [1au] AAAA? d1b10bmlvqabco.cloudfront.net. (58)
# 1606161615.637488 IP 192.168.3.214.49370 > 208.67.222.123.53: 28871+ [1au] AAAA? admin.video.ubc.ca. (47)
# 1606138378.712355 IP 192.168.3.216.39110 > 208.67.220.123.53: 5003+ A? xxx.zzz.net. (34)

if __name__ == '__main__':
    #                          1606161614.421928        IP             192.168.3.214.50284                                            > 208.67.222.123.53:                                                         62398+             [1au]                        AAAA?                  d1b10bmlvqabco.cloudfront.net. (58)
    dns_extractor=re.compile(r'(?P<timestamp>[\d\:\.]+) (?P<proto>\S+) (?P<source_host>\d+\.\d+\.\d+\.\d+)(?:\.(?P<source_port>\d+)) > (?P<destination_host>\d+\.\d+\.\d+\.\d+)(?:\.(?P<destination_port>\d+))?\: (?P<query_id>\S+)\+(?: \[(?P<operation>\S+)\])? (?P<query_class>\S+)\? (?P<query>\S+)\. \((?P<size>\d+)\)')
    for l in sys.stdin:
        m=dns_extractor.search(l)
        if m:
            print(json.dumps(m.groupdict()))
        else:
            raise Exception(l)