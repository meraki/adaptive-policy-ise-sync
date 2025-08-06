#!/usr/bin/env bash
# start-server.sh
(cd adaptive_policy_sync; cd sync; mkdir migrations; cd migrations; touch __init__.py)
(cd adaptive_policy_sync; python manage.py makemigrations --no-input; python manage.py migrate --no-input)
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] ; then
    (cd adaptive_policy_sync; python manage.py createsuperuser --no-input)
fi
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] && [ -n "$DJANGO_SUPERUSER_APIKEY" ] ; then
    (cd adaptive_policy_sync; python manage.py runscript import_token --script-args $DJANGO_SUPERUSER_USERNAME $DJANGO_SUPERUSER_APIKEY)
fi
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] && [ -n "$SIMULATED_ENVIRONMENT_URL" ] ; then
    (cd adaptive_policy_sync; python manage.py runscript dashboard_simulator --script-args 10 2 2 2; python manage.py runscript ise_ers_simulator --script-args 5 5 5; cd scripts; chown www-data:www-data *.json)
    echo "===================================================="
    echo "For Cisco ISE, use the following settings:"
    echo "1) IP Address: $SIMULATED_ENVIRONMENT_URL/ise"
    echo "2) Username/Password: (not required; enter anything)"
    echo "===================================================="
    echo "For Meraki Dashboard, use the following settings:"
    echo "1) Path: $SIMULATED_ENVIRONMENT_URL/meraki/api/v1"
    echo "2) API Key: (not required; enter anything)"
    echo "===================================================="
fi
(cd adaptive_policy_sync; python manage.py loaddata base_db.json)
(cd adaptive_policy_sync; chown -R www-data:www-data *)
(cd adaptive_policy_sync; python manage.py runscript tasks) &
(cd adaptive_policy_sync; gunicorn adaptive_policy_sync.wsgi --user www-data --bind 0.0.0.0:8010 --workers 1 --preload) &
nginx -g "daemon off;"
