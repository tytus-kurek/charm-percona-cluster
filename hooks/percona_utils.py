''' General utilities for percona '''
import subprocess
import socket
from charmhelpers.core.host import (
    lsb_release
)
from charmhelpers.core.hookenv import (
    unit_get,
    relation_ids,
    related_units,
    relation_get,
)
from charmhelpers.fetch import (
    apt_install,
    filter_installed_packages
)

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
    'percona-xtradb-cluster-client-5.5'
]

KEY = "keys/repo.percona.com"
REPO = """deb http://repo.percona.com/apt {release} main
deb-src http://repo.percona.com/apt {release} main"""
MY_CNF = "/etc/mysql/my.cnf"


def setup_percona_repo():
    with open('/etc/apt/sources.list.d/percona.list', 'w') as sources:
        sources.write(REPO.format(release=lsb_release()['DISTRIB_CODENAME']))
    subprocess.check_call(['apt-key', 'add', KEY])

TEMPLATES_DIR = 'templates'


def render_template(template_name, context, template_dir=TEMPLATES_DIR):
    templates = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_dir))
    template = templates.get_template(template_name)
    return template.render(context)


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
            hosts.append(get_host_ip(
                relation_get('private-address',
                             unit, relid))
            )
    return hosts

SQL_SST_USER_SETUP = """mysql -u root << EOF
CREATE USER 'sstuser'@'localhost' IDENTIFIED BY 's3cretPass';
GRANT RELOAD, LOCK TABLES, REPLICATION CLIENT ON *.* TO 'sstuser'@'localhost';
EOF"""


def configure_sstuser():
    subprocess.check_call(SQL_SST_USER_SETUP, shell=True)
