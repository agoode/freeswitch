#!/bin/bash

echo "Starting shutdown"

printenv

echo "Done shutting down"

./fs_cli -x 'fsctl shutdown now'
