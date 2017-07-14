#!/bin/bash

python manage.py makemigrations rest
python manage.py migrate
python manage.py shell -c "from lib import bootstrap_data_stores; bootstrap_data_stores()"
python manage.py createsuperuser
python manage.py shell -c "from rest.models import WsUser; user = WsUser.objects.first(); user.is_active = True; user.is_enterprise_user = True; user.email_verified = True; user.save()"