#!/bin/env python

import requests

import argparse
import json
from sys import stdin

if __name__ == '__main__':
    parser=argparse.ArgumentParser('es_poster')
    parser.add_argument('--es-uri')
    parser.add_argument('--es-index', default='logs')
    args=parser.parse_args()
    post_uri="{uri}/{index}/_doc/".format(uri=args.es_uri,index=args.es_index)
    for l in stdin:
        data=json.loads(l)
        data['_timestamp']=data['timestamp']
        r=requests.post(post_uri,data=json.dumps(data),headers={'Content-Type': 'application/json'})
        print(r.text)