#!/bin/bash

python manage.py shell -c "from lib.deploy import DeployChecker; checker = DeployChecker(); checker.print_status()"