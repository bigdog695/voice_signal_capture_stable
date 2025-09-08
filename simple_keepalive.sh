#!/bin/bash

# Simple keepalive receiver - discards all data but maintains the connection
nc -u -l 8900 > /dev/null
