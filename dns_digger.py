#!/bin/env python

import argparse
import json
import sys
import subprocess
import re

whois_cache={}

if __name__ == "__main__":
    parser=argparse.ArgumentParser('add DNS data to the stream')
    parser.add_argument('--dig-dst', action='store_true', default=False)
    parser.add_argument('--only-ip', action='store_true', default=False)
    parser.add_argument('--shorten-domain', type=int, default=None)

    args=parser.parse_args()
    orgname_re=re.compile(r'^OrgName:\s+')
    
    for l in sys.stdin:
        data=json.loads(l)
        if args.dig_dst:
            lines=[]
            if args.only_ip:
                if data['destination_host'] != data['resolved_dst']:
                    # we've already resolved this record, move on
                    continue
            if data['destination_host'] in whois_cache:
                lines=whois_cache[data['destination_host']]
            else:
                result=subprocess.run(['/bin/sh','-c','whois {} | grep -e OrgName'.format(data['destination_host'])],stdout=subprocess.PIPE)
                output=result.stdout.decode('utf-8')
                lines=output.split("\n")
                whois_cache[data['destination_host']]=lines
            entries=[]
            for line in lines:
                entry=orgname_re.sub('',line)
                if entry:
                    entries.append(entry)
            data['whois']=','.join(entries)
        if args.shorten_domain is not None:
            domain_list=data['resolved_dst'].split('.')
            domain='.'.join(domain_list[-args.shorten_domain:])
            data['short_domain']=domain
        print(json.dumps(data))
