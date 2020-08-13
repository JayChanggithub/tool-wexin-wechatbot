#!flask/bin/python
# -*- coding: utf-8 -*-
import multiprocessing

# preload_app = True
#workers = 8
threads = multiprocessing.cpu_count() * 2
workers = multiprocessing.cpu_count() * 2 + 1
# backlog = 2048
worker_class = 'gevent'
worker_connections = 1200
bind = '0.0.0.0:1990'
debug = True
proc_name = 'gunicorn.pid'
max_requests = 1200 
graceful_timeout = 3600 
timeout = 1200
pidfile = '/var/log/gunicorn/app_run.log'
loglevel = 'debug'
logfile = '/var/log/gunicorn/debug.log'
accesslog = '/var/log/gunicorn/access.log'
access_log_format = '%(h)s %(t)s %(U)s %(q)s'
