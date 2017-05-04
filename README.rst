pflog_stats
===========

Generate stats from pflog files

Usage
=====

::

    usage: pflog_stats.py [-h] [--regexp] [--filter-src FILTER_SRC]
                          [--filter-dst FILTER_DST] [--resolve-dst]
                          [--resolve-src]

    optional arguments:
      -h, --help            show this help message and exit
      --regexp              Criterion provided in filters shall be treated as
                            regexp
      --filter-src FILTER_SRC
                            print stats only for sources matching criteria
      --filter-dst FILTER_DST
                            print stats only for destinations matching criteria
      --resolve-dst         resolve destination IPs
      --resolve-src         resolve source IPs

