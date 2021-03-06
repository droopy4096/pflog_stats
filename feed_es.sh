#!/bin/sh

# datestamp=$(date '+%Y%m%d')
ES_HOST=${ES_HOST:-192.168.3.170}
ES_PORT=${ES_PORT:-9200}
# ES_INDEX_SUFFIX=${ES_INDEX_SUFFIX:-${datestamp}}

ES_URI=http://${ES_HOST}:${ES_PORT}
ES_INDEX_PREFIX=${ES_INDEX_PREFIX:-logs}

TCPDUMP_FILTER=${TCPDUMP_FILTER:-"tcp and host 192.168.3.214 or host 192.168.3.216"}


log_mark=/var/log/pflog_es.${ES_HOST}_${ES_PORT}

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
        datestamp=$(stat -f %Sm -t %Y%m%d ${log})
        ES_INDEX=${ES_INDEX_PREFIX}.${datestamp}
    fi
    curl -H 'Content-Type: application/json' -XPUT ${ES_URI}/${ES_INDEX} -d'
    {
        "mappings": {
            "dynamic": true,
            "properties": {
                "timestamp": {
                    "type": "date",
                    "format": "epoch_second"
                },
                "rule": { "type": "keyword" },
                "action": { "type": "keyword" },
                "direction": {"type": "keyword" },
                "interface": {"type": "keyword" },
                "source_host": {"type": "ip" },
                "source_port": {"type": "integer"},
                "destination_host": {"type": "ip"},
                "destination_port": {"type": "integer"},
                "resolved_dst": {"type": "keyword" },
                "whois": {"type": "keyword" },
                "short_domain": {"type": "keyword" },
                "details": {"type": "text"}
            }
        }
    }
    '
    /usr/bin/bzcat ${log} | \
        tcpdump -ttenr - ${TCPDUMP_FILTER} | \
        python3.7 ~dimon/pflog_stats.py --parser lines --format log --resolve-to-field --resolve-dst | \
        python3.7 ~dimon/dns_digger.py --dig-dst --only-ip --shorten-domain=2 | \
        python3.7 ~dimon/es_poster.py --es-uri=${ES_URI} --es-index=${ES_INDEX} 
    touch -r ${log} ${log_mark}
done
