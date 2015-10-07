''' General utilities for percona '''
import subprocess
from subprocess import Popen, PIPE
import socket
import tempfile
import os
import shutil
import uuid

from charmhelpers.core.host import (
    lsb_release
)
from charmhelpers.core.hookenv import (
    charm_dir,
    unit_get,
    relation_ids,
    related_units,
    relation_get,
    relation_set,
    local_unit,
    service_name,
    config,
    log,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
)
from charmhelpers.fetch import (
    apt_install,
    filter_installed_packages
)
from charmhelpers.contrib.network.ip import (
    get_ipv6_addr
)
from charmhelpers.contrib.database.mysql import (
    MySQLHelper,
)

# NOTE: python-mysqldb is installed by charmhelpers.contrib.database.mysql so
# hence why we import here
from MySQLdb import (
    OperationalError
)

KEY = "keys/repo.percona.com"
REPO = """deb http://repo.percona.com/apt {release} main
deb-src http://repo.percona.com/apt {release} main"""
MY_CNF = "/etc/mysql/my.cnf"
SEEDED_MARKER = "/var/lib/mysql/seeded"
HOSTS_FILE = '/etc/hosts'


def determine_packages():
    if lsb_release()['DISTRIB_CODENAME'] > 'utopic':
        # NOTE(beisner): pxc 5.6 client package is not available
        # in Vivid, install mysql 5.6 client instead per
        # https://launchpad.net/bugs/1476845.
        return [
            'percona-xtradb-cluster-server-5.6',
            'mysql-client-5.6'
        ]
    else:
        return [
            'percona-xtradb-cluster-server-5.5',
            'percona-xtradb-cluster-client-5.5',
        ]


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


def get_host_ip(hostname=None):
    try:
        import dns.resolver
    except ImportError:
        apt_install(filter_installed_packages(['python-dnspython']),
                    fatal=True)
        import dns.resolver

    if config('prefer-ipv6'):
        # Ensure we have a valid ipv6 address configured
        get_ipv6_addr(exc_list=[config('vip')], fatal=True)[0]
        return socket.gethostname()

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


def is_sufficient_peers():
    """If min-cluster-size has been provided, check that we have sufficient
    number of peers to proceed with bootstrapping percona cluster.
    """
    min_size = config('min-cluster-size')
    if min_size:
        size = 0
        for rid in relation_ids('cluster'):
            size = len(related_units(rid))

        # Include this unit
        size += 1
        if min_size > size:
            log("Insufficient number of units to configure percona cluster "
                "(expected=%s, got=%s)" % (min_size, size), level=INFO)
            return False
        else:
            log("Sufficient units available to configure percona cluster "
                "(>=%s)" % (min_size), level=DEBUG)

    return True


def get_cluster_hosts():
    hosts_map = {}
    hostname = get_host_ip()
    hosts = [hostname]
    # We need to add this localhost dns name to /etc/hosts along with peer
    # hosts to ensure percona gets consistently resolved addresses.
    if config('prefer-ipv6'):
        addr = get_ipv6_addr(exc_list=[config('vip')], fatal=True)[0]
        hosts_map = {addr: hostname}

    for relid in relation_ids('cluster'):
        for unit in related_units(relid):
            rdata = relation_get(unit=unit, rid=relid)
            private_address = rdata.get('private-address')
            if config('prefer-ipv6'):
                hostname = rdata.get('hostname')
                if not hostname or hostname in hosts:
                    log("(unit=%s) Ignoring hostname '%s' provided by cluster "
                        "relation for addr %s" %
                        (unit, hostname, private_address), level=DEBUG)
                    continue
                else:
                    log("(unit=%s) hostname '%s' provided by cluster relation "
                        "for addr %s" % (unit, hostname, private_address),
                        level=DEBUG)

                hosts_map[private_address] = hostname
                hosts.append(hostname)
            else:
                hosts.append(get_host_ip(private_address))

    if hosts_map:
        update_hosts_file(hosts_map)

    return hosts


SQL_SST_USER_SETUP = ("GRANT RELOAD, LOCK TABLES, REPLICATION CLIENT ON *.* "
                      "TO 'sstuser'@'localhost' IDENTIFIED BY '{}'")

SQL_SST_USER_SETUP_IPV6 = ("GRANT RELOAD, LOCK TABLES, REPLICATION CLIENT "
                           "ON *.* TO 'sstuser'@'ip6-localhost' IDENTIFIED "
                           "BY '{}'")


def get_db_helper():
    return MySQLHelper(rpasswdf_template='/var/lib/charm/%s/mysql.passwd' %
                       (service_name()),
                       upasswdf_template='/var/lib/charm/%s/mysql-{}.passwd' %
                       (service_name()))


def configure_sstuser(sst_password):
    m_helper = get_db_helper()
    m_helper.connect(password=m_helper.get_mysql_root_password())
    m_helper.execute(SQL_SST_USER_SETUP.format(sst_password))
    m_helper.execute(SQL_SST_USER_SETUP_IPV6.format(sst_password))


# TODO: mysql charmhelper
def configure_mysql_root_password(password):
    ''' Configure debconf with root password '''
    dconf = Popen(['debconf-set-selections'], stdin=PIPE)
    # Set both percona and mysql password options to cover
    # both upstream and distro packages.
    packages = ["percona-server-server", "mysql-server"]
    m_helper = get_db_helper()
    root_pass = m_helper.get_mysql_root_password(password)
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


def update_hosts_file(map):
    """Percona does not currently like ipv6 addresses so we need to use dns
    names instead. In order to make them resolvable we ensure they are  in
    /etc/hosts.

    See https://bugs.launchpad.net/galera/+bug/1130595 for some more info.
    """
    with open(HOSTS_FILE, 'r') as hosts:
        lines = hosts.readlines()

    log("Updating %s with: %s (current: %s)" % (HOSTS_FILE, map, lines),
        level=DEBUG)

    newlines = []
    for ip, hostname in map.items():
        if not ip or not hostname:
            continue

        keepers = []
        for line in lines:
            _line = line.split()
            if len(line) < 2 or not (_line[0] == ip or hostname in _line[1:]):
                keepers.append(line)
            else:
                log("Marking line '%s' for update or removal" % (line.strip()),
                    level=DEBUG)

        lines = keepers
        newlines.append("%s %s\n" % (ip, hostname))

    lines += newlines

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        with open(tmpfile.name, 'w') as hosts:
            for line in lines:
                hosts.write(line)

    os.rename(tmpfile.name, HOSTS_FILE)
    os.chmod(HOSTS_FILE, 0o644)


def assert_charm_supports_ipv6():
    """Check whether we are able to support charms ipv6."""
    if lsb_release()['DISTRIB_CODENAME'].lower() < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")


def unit_sorted(units):
    """Return a sorted list of unit names."""
    return sorted(
        units, lambda a, b: cmp(int(a.split('/')[-1]), int(b.split('/')[-1])))


def install_mysql_ocf():
    dest_dir = '/usr/lib/ocf/resource.d/percona/'
    for fname in ['ocf/percona/mysql_monitor']:
        src_file = os.path.join(charm_dir(), fname)
        if not os.path.isdir(dest_dir):
            os.makedirs(dest_dir)

        dest_file = os.path.join(dest_dir, os.path.basename(src_file))
        if not os.path.exists(dest_file):
            log('Installing %s' % dest_file, level='INFO')
            shutil.copy(src_file, dest_file)
        else:
            log("'%s' already exists, skipping" % dest_file, level='INFO')


def get_wsrep_value(key):
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", DEBUG)
        return None

    cursor = m_helper.connection.cursor()
    ret = None
    try:
        cursor.execute("show status like '%s'" % (key))
        ret = cursor.fetchall()
    except:
        log("Failed to get '%s'", ERROR)
        return None
    finally:
        cursor.close()

    if ret:
        return ret[0][1]

    return None


def is_bootstrapped():
    if not is_sufficient_peers():
        return False

    uuids = []
    rids = relation_ids('cluster') or []
    for rid in rids:
        units = related_units(rid)
        units.append(local_unit())
        for unit in units:
            id = relation_get('bootstrap-uuid', unit=unit, rid=rid)
            if id:
                uuids.append(id)

    if uuids:
        if len(set(uuids)) > 1:
            log("Found inconsistent bootstrap uuids - %s" % (uuids), WARNING)

        return True

    return False


def notify_bootstrapped(cluster_rid=None, cluster_uuid=None):
    if cluster_rid:
        rids = [cluster_rid]
    else:
        rids = relation_ids('cluster')
        if not rids:
            log("No relation ids found for 'cluster'", level=INFO)
            return

    if not cluster_uuid:
        cluster_uuid = get_wsrep_value('wsrep_cluster_state_uuid')
        if not cluster_uuid:
            cluster_uuid = str(uuid.uuid4())
            log("Could not determine cluster uuid so using '%s' instead" %
                (cluster_uuid), INFO)

    log("Notifying peers that percona is bootstrapped (uuid=%s)" %
        (cluster_uuid), DEBUG)
    for rid in rids:
        relation_set(relation_id=rid, **{'bootstrap-uuid': cluster_uuid})


def cluster_in_sync():
    '''Determines whether the current unit is in sync with the rest of the cluster'''
    ready = get_wsrep_value('wsrep_ready') or False
    sync_status = get_wsrep_value('wsrep_local_state') or 0
    if ready and int(sync_status) == 4:
        return True
    return False

