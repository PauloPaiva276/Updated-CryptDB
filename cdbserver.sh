mkdir shadow
mysql-src/mysql-proxy-0.8.5/bin/mysql-proxy --defaults-file=./mysql-proxy.cnf --proxy-lua-script=`pwd`/wrapper.lua --proxy-backend-addresses=$1:3306
