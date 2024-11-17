#!/bin/bash

source ../venv/bin/activate

echo increasing fd limit...
ulimit -n `ulimit -Hn`
echo new fd limit: `ulimit -n`

python stress_test.py
