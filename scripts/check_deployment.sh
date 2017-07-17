#!/bin/bash

echo "Sleeping to let Docker components start up..."
sleep(5)
python manage.py shell -c "from lib.deploy import DeployChecker; checker = DeployChecker(); checker.print_status()"