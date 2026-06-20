#!/bin/sh
# Start monitor in background, then exec gunicorn as PID 1.
python monitor.py &
exec gunicorn dashboard:app \
  --bind "0.0.0.0:${PORT:-8080}" \
  --workers 1 \
  --threads 4 \
  --timeout 120
