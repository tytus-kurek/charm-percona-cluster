''' General utilities for percona '''
import subprocess
from subprocess import Popen, PIPE
import socket
import os
from charmhelpers.core.host import (
    lsb_release,
)
from charmhelpers.core.hookenv import (
    unit_get,
    relation_ids,
    related_units,
    relation_get,
    relation_set,
    local_unit,
)
from charmhelpers.fetch import (
    apt_install,
    filter_installed_packages,
)
from mysql import get_mysql_root_password, MySQLHelper

try:
    import jinja2
except ImportError:
    apt_install(filter_installed_packages(['python-jinja2']),
                fatal=True)
    import jinja2

try:
    import dns.resolver
except ImportError:
    apt_install(filter_installed_packages(['python-dnspython']),
                fatal=True)
    import dns.resolver

PACKAGES = [
    'percona-xtradb-cluster-server-5.5',
    'percona-xtradb-cluster-client-5.5',
    'unison'
]

KEY = "keys/repo.percona.com"
REPO = """deb http://repo.percona.com/apt {release} main
deb-src http://repo.percona.com/apt {release} main"""
MY_CNF = "/etc/mysql/my.cnf"
SEEDED_MARKER = "/var/lib/mysql/seeded"


def seeded():
    ''' Check whether service unit is already seeded '''
    return os.path.exists(SEEDED_MARKER)


def mark_seeded():
    ''' Mark service unit as seeded '''
    with open(SEEDED_MARKER, 'w') as seeded:
        seeded.write('done')


def setup_percona_repo():
    ''' Configure service unit to use percona repositories '''
    with open('/etc/apt/sources.list.d/percona.list', 'w') as sources:
        sources.write(REPO.format(release=lsb_release()['DISTRIB_CODENAME']))
    subprocess.check_call(['apt-key', 'add', KEY])

TEMPLATES_DIR = 'templates'


def render_template(template_name, context, template_dir=TEMPLATES_DIR):
    templates = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_dir))
    template = templates.get_template(template_name)
    return template.render(context)


# TODO: goto charm-helpers (I use this everywhere)
def get_host_ip(hostname=None):
    hostname = hostname or unit_get('private-address')
    try:
        # Test to see if already an IPv4 address
        socket.inet_aton(hostname)
        return hostname
    except socket.error:
        # This may throw an NXDOMAIN exception; in which case
        # things are badly broken so just let it kill the hook
        answers = dns.resolver.query(hostname, 'A')
        if answers:
            return answers[0].address


def get_cluster_hosts():
    hosts = [get_host_ip()]
    for relid in relation_ids('cluster'):
        for unit in related_units(relid):
            hosts.append(get_host_ip(relation_get('private-address',
                                     unit, relid)))
    return hosts

SQL_SST_USER_SETUP = "GRANT RELOAD, LOCK TABLES, REPLICATION CLIENT ON *.*" \
    " TO 'sstuser'@'localhost' IDENTIFIED BY '{}'"


def configure_sstuser(sst_password):
    m_helper = MySQLHelper()
    m_helper.connect(password=get_mysql_root_password())
    m_helper.execute(SQL_SST_USER_SETUP.format(sst_password))


# TODO: mysql charmhelper
def configure_mysql_root_password(password):
    ''' Configure debconf with root password '''
    dconf = Popen(['debconf-set-selections'], stdin=PIPE)
    # Set both percona and mysql password options to cover
    # both upstream and distro packages.
    packages = ["percona-server-server", "mysql-server"]
    root_pass = get_mysql_root_password(password)
    for package in packages:
        dconf.stdin.write("%s %s/root_password password %s\n" %
                          (package, package, root_pass))
        dconf.stdin.write("%s %s/root_password_again password %s\n" %
                          (package, package, root_pass))
    dconf.communicate()
    dconf.wait()


# TODO: Submit for charmhelper
def relation_clear(r_id=None):
    ''' Clears any relation data already set on relation r_id '''
    settings = relation_get(rid=r_id,
                            unit=local_unit())
    for setting in settings:
        if setting not in ['public-address', 'private-address']:
            settings[setting] = None
    relation_set(relation_id=r_id,
                 **settings)
