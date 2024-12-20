#!/bin/bash
source venv/bin/activate

echo increasing fd limit...
ulimit -n `ulimit -Hn`
echo new fd limit: `ulimit -n`

SERVER_CONFIG_PATH='./devel_config.yml' uwsgi --master --processes 8 --http-socket '127.0.0.1:6969' --http-raw-body --gevent 5000 --module app --stats 127.0.0.1:9191 --gevent-monkey-patch

