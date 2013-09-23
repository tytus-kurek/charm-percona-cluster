''' Helper for working with a MySQL database '''
# TODO: Contribute to charm-helpers
import socket
import os
import re
import sys
import platform
from string import upper
from charmhelpers.core.host import pwgen, write_file, mkdir
from charmhelpers.core.hookenv import unit_get, service_name
from charmhelpers.core.hookenv import config as config_get
from charmhelpers.fetch import apt_install, filter_installed_packages


try:
    import MySQLdb
except ImportError:
    apt_install(filter_installed_packages(['python-mysqldb']),
                fatal=True)
    import MySQLdb


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
            cursor.execute("CREATE DATABASE {} CHARACTER SET UTF8"
                           .format(db_name))
        finally:
            cursor.close()

    def grant_exists(self, db_name, db_user, remote_ip):
        cursor = self.connection.cursor()
        try:
            cursor.execute("SHOW GRANTS for '{}'@'{}'".format(db_user,
                                                              remote_ip))
            grants = [i[0] for i in cursor.fetchall()]
        except MySQLdb.OperationalError:
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

    def create_admin_grant(self, db_user,
                           remote_ip, password):
        cursor = self.connection.cursor()
        try:
            cursor.execute("GRANT ALL PRIVILEGES ON *.* TO '{}'@'{}' "
                           "IDENTIFIED BY '{}'".format(db_user,
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

    def execute(self, sql):
        ''' Execute arbitary SQL against the database '''
        cursor = self.connection.cursor()
        try:
            cursor.execute(sql)
        finally:
            cursor.close()


_root_passwd = '/var/lib/charm/{}/mysql.passwd'
_named_passwd = '/var/lib/charm/{}/mysql-{}.passwd'


def get_mysql_password(username=None, password=None):
    ''' Retrieve, generate or store a mysql password for
        the provided username '''
    if username:
        _passwd_file = _named_passwd.format(service_name(),
                                            username)
    else:
        _passwd_file = _root_passwd.format(service_name())
    _password = None
    if os.path.exists(_passwd_file):
        with open(_passwd_file, 'r') as passwd:
            _password = passwd.read().strip()
    else:
        mkdir(os.path.dirname(_passwd_file),
              owner='root', group='root',
              perms=0770)
        # Force permissions - for some reason the chmod in makedirs fails
        os.chmod(os.path.dirname(_passwd_file), 0770)
        _password = password or pwgen(length=32)
        write_file(_passwd_file, _password,
                   owner='root', group='root',
                   perms=0660)
    return _password


def get_mysql_root_password(password=None):
    ''' Retrieve or generate mysql root password for service units '''
    return get_mysql_password(username=None, password=password)


def configure_db(hostname,
                 database,
                 username,
                 admin=False):
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
        if not admin:
            m_helper.create_grant(database,
                                  username,
                                  remote_ip, password)
        else:
            m_helper.create_admin_grant(username,
                                        remote_ip, password)
    return password

# Going for the biggest page size to avoid wasted bytes. InnoDB page size is
# 16MB
DEFAULT_PAGE_SIZE = 16 * 1024 * 1024


def human_to_bytes(human):
    ''' Convert human readable configuration options to bytes '''
    num_re = re.compile('^[0-9]+$')
    if num_re.match(human):
        return human
    factors = {
        'K': 1024,
        'M': 1048576,
        'G': 1073741824,
        'T': 1099511627776
    }
    modifier = human[-1]
    if modifier in factors:
        return int(human[:-1]) * factors[modifier]
    if modifier == '%':
        total_ram = human_to_bytes(get_mem_total())
        if is_32bit_system() and total_ram > sys_mem_limit():
            total_ram = sys_mem_limit()
        factor = int(human[:-1]) * 0.01
        pctram = total_ram * factor
        return int(pctram - (pctram % DEFAULT_PAGE_SIZE))
    raise ValueError("Can only convert K,M,G, or T")


def is_32bit_system():
    ''' Determine whether system is 32 or 64 bit '''
    try:
        _is_32bit_system = sys.maxsize < 2 ** 32
    except OverflowError:
        _is_32bit_system = True
    return _is_32bit_system


def sys_mem_limit():
    ''' Determine the default memory limit for the current service unit '''
    if platform.machine() in ['armv7l']:
        _mem_limit = human_to_bytes('2700M')  # experimentally determined
    else:
        # Limit for x86 based 32bit systems
        _mem_limit = human_to_bytes('4G')
    return _mem_limit


def get_mem_total():
    ''' Calculate the total memory in the current service unit '''
    with open('/proc/meminfo') as meminfo_file:
        for line in meminfo_file:
            (key, mem) = line.split(':', 2)
            if key == 'MemTotal':
                (mtot, modifier) = mem.strip().split(' ')
                return '%s%s' % (mtot, upper(modifier[0]))


def parse_config():
    ''' Parse charm configuration and calculate values for config files '''
    config = config_get()
    mysql_config = {}
    if 'max-connections' in config:
        mysql_config['max_connections'] = config['max-connections']

    # Total memory available for dataset
    dataset_bytes = human_to_bytes(config['dataset-size'])
    mysql_config['dataset_bytes'] = dataset_bytes

    if 'query-cache-type' in config:
        # Query Cache Configuration
        mysql_config['query_cache_size'] = config['query-cache-size']
        if (config['query-cache-size'] == -1 and
                config['query-cache-type'] in ['ON', 'DEMAND']):
            # Calculate the query cache size automatically
            qcache_bytes = (dataset_bytes * 0.20)
            qcache_bytes = int(qcache_bytes -
                               (qcache_bytes % DEFAULT_PAGE_SIZE))
            mysql_config['query_cache_size'] = qcache_bytes
            dataset_bytes -= qcache_bytes
        # 5.5 allows the words, but not 5.1
        if config['query-cache-type'] == 'ON':
            mysql_config['query_cache_type'] = 1
        elif config['query-cache-type'] == 'DEMAND':
            mysql_config['query_cache_type'] = 2
        else:
            mysql_config['query_cache_type'] = 0

    # Set a sane default key_buffer size
    mysql_config['key_buffer'] = human_to_bytes('32M')

    if 'preferred-storage-engine' in config:
        # Storage engine configuration
        preferred_engines = config['preferred-storage-engine'].split(',')
        chunk_size = int(dataset_bytes / len(preferred_engines))
        mysql_config['innodb_flush_log_at_trx_commit'] = 1
        mysql_config['sync_binlog'] = 1
        if 'InnoDB' in preferred_engines:
            mysql_config['innodb_buffer_pool_size'] = chunk_size
            if config['tuning-level'] == 'fast':
                mysql_config['innodb_flush_log_at_trx_commit'] = 2
        else:
            mysql_config['innodb_buffer_pool_size'] = 0
        mysql_config['default_storage_engine'] = preferred_engines[0]
        if 'MyISAM' in preferred_engines:
            mysql_config['key_buffer'] = chunk_size
        if config['tuning-level'] == 'fast':
            mysql_config['sync_binlog'] = 0
    return mysql_config
