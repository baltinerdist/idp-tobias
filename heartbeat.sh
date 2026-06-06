#/bin/sh

mkdir -p /var/www/idp.amtgard.com/logs
chown www-data:www-data /var/www/idp.amtgard.com/logs 2>/dev/null || true

/usr/sbin/service nginx start
/usr/sbin/service php8.4-fpm start
/usr/sbin/service memcached start
/usr/sbin/service redis-server start

while true; do sleep 1; done
