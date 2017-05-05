pflog_stats
===========

Generate stats from pflog files. It is an in-line filter used in pipelines::

    tcpdump -enr pflog.0 | python pflog_stats.py

inspired by https://forums.freebsd.org/threads/3592/

Usage
=====

::

    usage: pflog_stats.py [-h] [--regexp] [--select-timestamp TIMESTAMP]
			  [--select-rule RULE] [--select-action ACTION]
			  [--select-direction DIRECTION]
			  [--select-interface INTERFACE]
			  [--select-source-host SOURCE_HOST]
			  [--select-source-port SOURCE_PORT]
			  [--select-destination-host DESTINATION_HOST]
			  [--select-destination-port DESTINATION_PORT]
			  [--resolve-dst] [--resolve-src] [--parser {stats,lines}]
			  [--output-field {timestamp,rule,action,direction,interface,source_host,source_port,destination_host,destination_port}]
			  [--format {compact,pretty}]

    Parse pflog output produced by "tcpdump -ne"

    optional arguments:
      -h, --help            show this help message and exit
      --regexp              Criterion provided in filters shall be treated as
			    regexp
      --select-timestamp TIMESTAMP
			    select timestamp matching lines
      --select-rule RULE    select rule matching lines
      --select-action ACTION
			    select action matching lines
      --select-direction DIRECTION
			    select direction matching lines
      --select-interface INTERFACE
			    select interface matching lines
      --select-source-host SOURCE_HOST
			    select source-host matching lines
      --select-source-port SOURCE_PORT
			    select source-port matching lines
      --select-destination-host DESTINATION_HOST
			    select destination-host matching lines
      --select-destination-port DESTINATION_PORT
			    select destination-port matching lines
      --resolve-dst         resolve destination IPs
      --resolve-src         resolve source IPs
      --parser {stats,lines}
      --output-field {timestamp,rule,action,direction,interface,source_host,source_port,destination_host,destination_port}
      --format {compact,pretty}

