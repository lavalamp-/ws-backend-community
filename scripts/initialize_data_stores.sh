#!/bin/bash

python manage.py makemigrations rest
python manage.py migrate
python manage.py shell -c "from lib import bootstrap_data_stores; bootstrap_data_stores()"
python manage.py createsuperuser