#!/bin/bash
mitmdump --mode reverse:http://127.0.0.1:8000 -p 8080 -s filter.py --set block_global=false --no-http2 &
gunicorn --threads 8 --bind 127.0.0.1:8000 flask_autoindex.run:app
