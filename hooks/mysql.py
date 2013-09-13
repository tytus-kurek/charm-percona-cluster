''' Helper for working with a MySQL database '''
# TODO: Contribute to charm-helpers
import MySQLdb
import socket
import os

from charmhelpers.core.host import pwgen
from charmhelpers.core.hookenv import unit_get


class MySQLHelper():
    def __init__(self, host='localhost'):
        self.host = host

    def connect(self, user='root', password=None):
        self.connection = MySQLdb.connect(user=user, host=self.host,
                                          passwd=password)

    def database_exists(self, db_name):
        cursor = self.connection.cursor()
        try:
            cursor.execute("SHOW DATABASES")
            databases = [i[0] for i in cursor.fetchall()]
        finally:
            cursor.close()
        return db_name in databases

    def create_database(self, db_name):
        cursor = self.connection.cursor()
        try:
            cursor.execute("CREATE DATABASE {}".format(db_name))
        finally:
            cursor.close()

    def grant_exists(self, db_name, db_user, remote_ip):
        cursor = self.connection.cursor()
        try:
            cursor.execute("SHOW GRANTS for '{}'@'{}'".format(db_user,
                                                              remote_ip))
            grants = [i[0] for i in cursor.fetchall()]
        except MySQLdb.OperationalError:
            print "No grants found"
            return False
        finally:
            cursor.close()
        # TODO: review for different grants
        return "GRANT ALL PRIVILEGES ON `{}`".format(db_name) in grants

    def create_grant(self, db_name, db_user,
                     remote_ip, password):
        cursor = self.connection.cursor()
        try:
            # TODO: review for different grants
            cursor.execute("GRANT ALL PRIVILEGES ON {}.* TO '{}'@'{}' "
                           "IDENTIFIED BY '{}'".format(db_name,
                                                       db_user,
                                                       remote_ip,
                                                       password))
        finally:
            cursor.close()

    def cleanup_grant(self, db_user,
                      remote_ip):
        cursor = self.connection.cursor()
        try:
            cursor.execute("DROP FROM mysql.user WHERE user='{}' "
                           "AND HOST='{}'".format(db_user,
                                                  remote_ip))
        finally:
            cursor.close()

_root_passwd = '/var/lib/mysql/mysql.passwd'
_named_passwd = '/var/lib/mysql/mysql-{}.passwd'


def get_mysql_password(username=None):
    ''' Retrieve or generate a mysql password for the provided username '''
    if username:
        _passwd_file = _named_passwd.format(username)
    else:
        _passwd_file = _root_passwd
    password = None
    if os.path.exists(_passwd_file):
        with open(_passwd_file, 'r') as passwd:
            password = passwd.read().strip()
    else:
        if not os.path.exists(os.path.dirname(_passwd_file)):
            os.makedirs(os.path.dirname(_passwd_file))
        password = pwgen(length=32)
        with open(_passwd_file, 'w') as passwd:
            passwd.write(password)
        os.chmod(_passwd_file, 0600)
    return password


def get_mysql_root_password():
    ''' Retrieve or generate mysql root password for service units '''
    return get_mysql_password()


def configure_db(hostname,
                 database,
                 username):
    ''' Configure access to database for username from hostname '''
    if hostname != unit_get('private-address'):
        remote_ip = socket.gethostbyname(hostname)
    else:
        remote_ip = '127.0.0.1'

    password = get_mysql_password(username)
    m_helper = MySQLHelper()
    m_helper.connect(password=get_mysql_root_password())
    if not m_helper.database_exists(database):
        m_helper.create_database(database)
    if not m_helper.grant_exists(database,
                                 username,
                                 remote_ip):
        m_helper.create_grant(database,
                              username,
                              remote_ip, password)
    return password
