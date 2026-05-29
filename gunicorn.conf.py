import multiprocessing

bind = "0.0.0.0:8075"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gevent"
worker_connections = 500
timeout = 120
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
proc_name = "tsun-ff-info-api"
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190
preload_app = True
max_requests = 5000
max_requests_jitter = 500
