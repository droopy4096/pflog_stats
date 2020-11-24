#!/bin/sh

# datestamp=$(date '+%Y%m%d')
ES_HOST=${ES_HOST:-192.168.3.170}
ES_PORT=${ES_PORT:-9200}
# ES_INDEX_SUFFIX=${ES_INDEX_SUFFIX:-${datestamp}}
ES_INDEX_PREFIX=${ES_INDEX_PREFIX:-dns}

ES_URI=http://${ES_HOST}:${ES_PORT}

TCPDUMP_FILTER=${TCPDUMP_FILTER:-"( host 192.168.3.214 or host 192.168.3.216 ) and port 53"}


# {'timestamp': '1606161614.421928',
#  'proto': 'IP',
#  'source_host': '192.168.3.214',
#  'source_port': '50284',
#  'destination_host': '208.67.222.123',
#  'destination_port': '53',
#  'query_id': '62398',
#  'operation': '1au',
#  'query_class': 'AAAA',
#  'query': 'd1b10bmlvqabco.cloudfront.net',
#  'size': '58'}
# 

curl -H 'Content-Type: application/json' -XPUT ${ES_URI}/${ES_INDEX} -d'
{
    "mappings": {
        "dynamic": true,
        "properties": {
            "timestamp": {
                "type": "date",
                "format": "epoch_second"
            },
            "proto": { "type": "keyword" },
            "source_host": { "type": "ip" },
            "source_port": {"type": "integer"},
            "destination_host": {"type": "ip"},
            "destination_port": {"type": "integer"},
            "query": {"type": "keyword" },
            "query_id": {"type": "integer" },
            "query_class": {"type": "keyword" },
            "operation": {"type": "keyword" },
            "size": {"type": "integer"}
        }
    }
}
'

log_mark=/var/log/pflog_dns_es.loaded

if [ -r ${log_mark} ]
then
    logs=$(find /var/log -name pflog.\* -a -newer ${log_mark} | xargs ls -D %s -l | sort -n -k 6 | awk '{print $7;}')
else
    logs=$(ls -1t /var/log/pflog.*.bz2 | sort -r)
fi

set -e
for log in ${logs}
do
    if [ -n "${ES_INDEX_SUFFIX}" ]
    then
        ES_INDEX=${ES_INDEX_PREFIX}.${ES_INDEX_SUFFIX}
    else
        datesampp=$(stat -f %Sm -t %Y%m%d ${log})
        ES_INDEX=${ES_INDEX_PREFIX}.${datestamp}
    fi
    /usr/bin/bzcat ${log} | \
        tcpdump -ttnr - ${TCPDUMP_FILTER} | \
        python3.7 ~dimon/pflog_stats_dns.py | \
        python3.7 ~dimon/es_poster.py --es-uri=${ES_URI} --es-index=${ES_INDEX} 
    touch -r ${log} ${log_mark}
done
