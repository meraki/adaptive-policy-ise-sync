# Dockerfile

# FROM directive instructing base image to build upon
FROM python:3.7-buster
RUN apt-get update && apt-get install nginx vim curl -y --no-install-recommends
COPY nginx.default /etc/nginx/sites-available/default
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# copy source and install dependencies
RUN mkdir -p /opt/app
RUN mkdir -p /opt/app/pip_cache
RUN mkdir -p /opt/app/adaptive_policy_sync
RUN mkdir -p /opt/app/adaptive_policy_sync/config
RUN mkdir -p /opt/app/adaptive_policy_sync/upload
COPY requirements.txt start-server.sh /opt/app/
#COPY .pip_cache /opt/app/pip_cache/
COPY . /opt/app/adaptive_policy_sync
WORKDIR /opt/app
RUN pip install -r requirements.txt --cache-dir /opt/app/pip_cache
#RUN touch /opt/app/adaptive_policy_sync/db.sqlite3
RUN chown -R www-data:www-data /opt/app
COPY cli /usr/local/bin

# start server
EXPOSE 8000
STOPSIGNAL SIGTERM
CMD ["/opt/app/start-server.sh"]
