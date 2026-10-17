#!/bin/bash
# MySQL 컨테이너 최초 기동 시 1회 실행. 비밀번호는 환경변수에서만 읽는다.
set -euo pipefail
for DB in nexus nexus_test; do
  mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"
  mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$DB" < /seed/schema.sql
  sed -e "s/__DB__/$DB/g" \
      -e "s/__APP_PW__/$NEXUS_APP_PASSWORD/g" \
      -e "s/__CONF_PW__/$NEXUS_CONF_PASSWORD/g" /seed/grants.sql \
    | mysql -uroot -p"$MYSQL_ROOT_PASSWORD"
done
mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"
