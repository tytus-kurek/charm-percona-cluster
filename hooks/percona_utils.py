''' General utilities for percona '''
import subprocess
from subprocess import Popen, PIPE
import socket
import tempfile
import os
import shutil
import uuid
from functools import partial

from charmhelpers.core.decorators import retry_on_exception
from charmhelpers.core.host import (
    lsb_release,
    mkdir,
    service,
    pwgen,
    CompareHostReleases,
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
    cached,
    status_set,
    network_get_primary_address,
    application_version_set,
    is_leader,
    leader_get,
    leader_set,
)
from charmhelpers.fetch import (
    apt_install,
    filter_installed_packages,
    get_upstream_version,
)
from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_ipv6_addr,
    is_ip,
)
from charmhelpers.contrib.database.mysql import (
    MySQLHelper,
)
from charmhelpers.contrib.openstack.utils import (
    make_assess_status_func,
    pause_unit,
    resume_unit,
    is_unit_paused_set,
)

# NOTE: python-mysqldb is installed by charmhelpers.contrib.database.mysql so
# hence why we import here
from MySQLdb import (
    OperationalError
)

KEY = "keys/repo.percona.com"
REPO = """deb http://repo.percona.com/apt {release} main
deb-src http://repo.percona.com/apt {release} main"""
SEEDED_MARKER = "{data_dir}/seeded"
HOSTS_FILE = '/etc/hosts'
DEFAULT_MYSQL_PORT = 3306

# NOTE(ajkavanagh) - this is 'required' for the pause/resume code for
# maintenance mode, but is currently not populated as the
# charm_check_function() checks whether the unit is working properly.
REQUIRED_INTERFACES = {}


class LeaderNoBootstrapUUIDError(Exception):
    """Raised when the leader doesn't have set the bootstrap-uuid attribute"""
    def __init__(self):
        super(LeaderNoBootstrapUUIDError, self).__init__(
            "the leader doesn't have set the bootstrap-uuid attribute")


class InconsistentUUIDError(Exception):
    """Raised when the leader and the unit have different UUIDs set"""
    def __init__(self, leader_uuid, unit_uuid):
        super(InconsistentUUIDError, self).__init__(
            "Leader UUID ('%s') != Unit UUID ('%s')" % (leader_uuid,
                                                        unit_uuid))


class DesyncedException(Exception):
    '''Raised if PXC unit is not in sync with its peers'''
    pass


class FakeOSConfigRenderer(object):
    """This class is to provide to register_configs() as a 'fake'
    OSConfigRenderer object that has a complete_contexts method that returns
    an empty list.  This is so that the pause/resume framework can be used
    from charmhelpers that requires configs to be able to run.
    This is a bit of a hack, but via Python's duck-typing enables the function
    to work.
    """
    def complete_contexts(self):
        return []


def determine_packages():
    if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) >= 'wily':
        # NOTE(beisner): Use recommended mysql-client package
        # https://launchpad.net/bugs/1476845
        # https://launchpad.net/bugs/1571789
        return [
            'percona-xtradb-cluster-server-5.6',
        ]
    else:
        return [
            'percona-xtradb-cluster-server-5.5',
            'percona-xtradb-cluster-client-5.5',
        ]


def seeded():
    ''' Check whether service unit is already seeded '''
    return os.path.exists(SEEDED_MARKER.format(data_dir=resolve_data_dir()))


def mark_seeded():
    ''' Mark service unit as seeded '''
    with open(SEEDED_MARKER.format(data_dir=resolve_data_dir()),
              'w') as seeded:
        seeded.write('done')


def setup_percona_repo():
    ''' Configure service unit to use percona repositories '''
    with open('/etc/apt/sources.list.d/percona.list', 'w') as sources:
        sources.write(REPO.format(release=lsb_release()['DISTRIB_CODENAME']))
    subprocess.check_call(['apt-key', 'add', KEY])


def resolve_hostname_to_ip(hostname, ipv6=False):
    """Resolve hostname to IP

    @param hostname: hostname to be resolved
    @returns IP address or None if resolution was not possible via DNS
    """
    try:
        import dns.resolver
    except ImportError:
        apt_install(filter_installed_packages(['python-dnspython']),
                    fatal=True)
        import dns.resolver

    if is_ip(hostname):
        return hostname
    else:
        if ipv6:
            query_type = 'AAAA'
        else:
            query_type = 'A'
        # This may throw an NXDOMAIN exception; in which case
        # things are badly broken so just let it kill the hook
        answers = dns.resolver.query(hostname, query_type)
        if answers:
            return answers[0].address


def is_sufficient_peers():
    """Sufficient number of expected peers to build a complete cluster

    If min-cluster-size has been provided, check that we have sufficient
    number of peers as expected for a complete cluster.

    If not defined assume a single unit.

    @returns boolean
    """

    min_size = config('min-cluster-size')
    if min_size:
        log("Checking for minimum of {} peer units".format(min_size),
            level=DEBUG)

        # Include this unit
        units = 1
        for rid in relation_ids('cluster'):
            units += len(related_units(rid))

        if units < min_size:
            log("Insufficient number of peer units to form cluster "
                "(expected=%s, got=%s)" % (min_size, units), level=INFO)
            return False
        else:
            log("Sufficient number of peer units to form cluster {}"
                "".format(min_size, level=DEBUG))
            return True
    else:
        log("min-cluster-size is not defined, race conditions may occur if "
            "this is not a single unit deployment.", level=WARNING)
        return True


def get_cluster_hosts():
    hosts_map = {}

    local_cluster_address = get_cluster_host_ip()

    # We need to add this localhost dns name to /etc/hosts along with peer
    # hosts to ensure percona gets consistently resolved addresses.
    if config('prefer-ipv6'):
        addr = get_ipv6_addr(exc_list=[config('vip')], fatal=True)[0]
        hosts_map = {addr: socket.gethostname()}

    hosts = [local_cluster_address]
    for relid in relation_ids('cluster'):
        for unit in related_units(relid):
            rdata = relation_get(unit=unit, rid=relid)
            # NOTE(dosaboy): see LP: #1599447
            cluster_address = rdata.get('cluster-address',
                                        rdata.get('private-address'))
            if config('prefer-ipv6'):
                hostname = rdata.get('hostname')
                if not hostname or hostname in hosts:
                    log("(unit=%s) Ignoring hostname '%s' provided by cluster "
                        "relation for addr %s" %
                        (unit, hostname, cluster_address), level=DEBUG)
                    continue
                else:
                    log("(unit=%s) hostname '%s' provided by cluster relation "
                        "for addr %s" % (unit, hostname, cluster_address),
                        level=DEBUG)

                hosts_map[cluster_address] = hostname
                hosts.append(hostname)
            else:
                hosts.append(resolve_hostname_to_ip(cluster_address))

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
    packages = ["percona-server-server", "mysql-server",
                "percona-xtradb-cluster-server"]
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
    _release = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(_release) < "trusty":
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
    """ Check that this unit is bootstrapped

    @returns boolean
    """
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


def bootstrap_pxc():
    """Bootstrap PXC
    On systemd systems systemctl bootstrap-pxc mysql does not work.
    Run service mysql bootstrap-pxc to bootstrap."""
    service('stop', 'mysql')
    bootstrapped = service('bootstrap-pxc', 'mysql')
    if not bootstrapped:
        try:
            # NOTE(jamespage): execute under systemd-run to ensure
            #                  that the bootstrap-pxc mysqld does
            #                  not end up in the juju unit daemons
            #                  cgroup scope.
            cmd = ['systemd-run', '--service-type=forking',
                   'service', 'mysql', 'bootstrap-pxc']
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as e:
            msg = 'Bootstrap PXC failed'
            error_msg = '{}: {}'.format(msg, e)
            status_set('blocked', msg)
            log(error_msg, ERROR)
            raise Exception(error_msg)
        # To make systemd aware mysql is running after a bootstrap
        service('start', 'mysql')
    log("Bootstrap PXC Succeeded", DEBUG)


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
    if is_leader():
        leader_set(**{'bootstrap-uuid': cluster_uuid})


def update_bootstrap_uuid():
    """This function verifies if the leader has set the bootstrap-uuid
    attribute to then check it against the running cluster uuid, if the check
    succeeds the bootstrap-uuid field is set in the cluster relation.

    :returns: True if the cluster UUID was updated, False if the local UUID is
              empty.
    """

    lead_cluster_state_uuid = leader_get('bootstrap-uuid')
    if not lead_cluster_state_uuid:
        log('Leader has not set bootstrap-uuid', level=DEBUG)
        raise LeaderNoBootstrapUUIDError()

    wsrep_ready = get_wsrep_value('wsrep_ready') or ""
    log("wsrep_ready: '%s'" % wsrep_ready, DEBUG)
    if wsrep_ready.lower() in ['on', 'ready']:
        cluster_state_uuid = get_wsrep_value('wsrep_cluster_state_uuid')
    else:
        cluster_state_uuid = None

    if not cluster_state_uuid:
        log("UUID is empty: '%s'" % cluster_state_uuid, level=DEBUG)
        return False
    elif lead_cluster_state_uuid != cluster_state_uuid:
        # this may mean 2 things:
        # 1) the units have diverged, which it's bad and we do stop.
        # 2) cluster_state_uuid could not be retrieved because it
        # hasn't been bootstrapped, mysqld is stopped, etc.
        log('bootstrap uuid differs: %s != %s' % (lead_cluster_state_uuid,
                                                  cluster_state_uuid),
            level=ERROR)
        raise InconsistentUUIDError(lead_cluster_state_uuid,
                                    cluster_state_uuid)

    for rid in relation_ids('cluster'):
        notify_bootstrapped(cluster_rid=rid,
                            cluster_uuid=cluster_state_uuid)

    return True


def cluster_in_sync():
    '''
    Determines whether the current unit is in sync
    with the rest of the cluster
    '''
    ready = get_wsrep_value('wsrep_ready') or False
    sync_status = get_wsrep_value('wsrep_local_state') or 0
    if ready and int(sync_status) in [2, 4]:
        return True
    return False


def charm_check_func():
    """Custom function to assess the status of the current unit

    @returns (status, message) - tuple of strings if an issue
    """

    @retry_on_exception(num_retries=10,
                        base_delay=2,
                        exc_type=DesyncedException)
    def _cluster_in_sync():
        '''Helper func to wait for a while for resync to occur

        @raise DesynedException: raised if local unit is not in sync
                                 with its peers
        '''
        if not cluster_in_sync():
            raise DesyncedException()

    min_size = config('min-cluster-size')
    # Ensure that number of peers > cluster size configuration
    if not is_sufficient_peers():
        return ('blocked', 'Insufficient peers to bootstrap cluster')

    if min_size and int(min_size) > 1:
        # Once running, ensure that cluster is in sync
        # and has the required peers
        if not is_bootstrapped():
            return ('waiting', 'Unit waiting for cluster bootstrap')
        elif is_bootstrapped():
            try:
                _cluster_in_sync()
                return ('active', 'Unit is ready and clustered')
            except DesyncedException:
                return ('blocked', 'Unit is not in sync')
    else:
        return ('active', 'Unit is ready')


@cached
def resolve_data_dir():
    _release = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(_release) < 'vivid':
        return '/var/lib/mysql'
    else:
        return '/var/lib/percona-xtradb-cluster'


@cached
def resolve_cnf_file():
    _release = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(_release) < 'vivid':
        return '/etc/mysql/my.cnf'
    else:
        return '/etc/mysql/percona-xtradb-cluster.conf.d/mysqld.cnf'


def register_configs():
    """Return a OSConfigRenderer object.
    However, ceph-mon wasn't written using OSConfigRenderer objects to do the
    config files, so this just returns an empty OSConfigRenderer object.

    @returns empty FakeOSConfigRenderer object.
    """
    return FakeOSConfigRenderer()


def services():
    """Return a list of services that are managed by this charm.

    @returns [services] - list of strings that are service names.
    """
    return ['mysql']


def assess_status(configs):
    """Assess status of current unit
    Decides what the state of the unit should be based on the current
    configuration.
    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    assess_status_func(configs)()
    if pxc_installed():
        application_version_set(get_upstream_version(determine_packages()[0]))


def assess_status_func(configs):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    NOTE(ajkavanagh) ports are not checked due to race hazards with services
    that don't behave sychronously w.r.t their service scripts.  e.g.
    apache2.
    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    return make_assess_status_func(
        configs, REQUIRED_INTERFACES,
        charm_func=lambda _: charm_check_func(),
        services=services(), ports=None)


def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit
    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    # TODO(ajkavanagh) - ports= has been left off because of the race hazard
    # that exists due to service_start()
    f(assess_status_func(configs),
      services=services(),
      ports=None)


def create_binlogs_directory():
    binlogs_directory = os.path.dirname(config('binlogs-path'))
    data_dir = resolve_data_dir() + '/'
    if binlogs_directory.startswith(data_dir):
        raise Exception("Configured binlogs directory (%s) must not be inside "
                        "mysql data dir" % (binlogs_directory))

    if not os.path.isdir(binlogs_directory):
        mkdir(binlogs_directory, 'mysql', 'mysql', 0o750)


def get_cluster_host_ip():
    """Get the this host's IP address for use with percona cluster peers

    @returns IP to pass to cluster peers
    """

    cluster_network = config('cluster-network')
    if cluster_network:
        cluster_addr = get_address_in_network(cluster_network, fatal=True)
    else:
        try:
            cluster_addr = network_get_primary_address('cluster')
        except NotImplementedError:
            # NOTE(jamespage): fallback to previous behaviour
            cluster_addr = resolve_hostname_to_ip(
                unit_get('private-address')
            )

    return cluster_addr


def cluster_ready():
    """Determine if each node in the cluster is ready and the cluster is
    complete with the expected number of peers.

    Once cluster_ready returns True it is safe to execute client relation
    hooks. Having min-cluster-size set will guarantee cluster_ready will not
    return True until the expected number of peers are clustered and ready.

    If min-cluster-size is not set it must assume the cluster is ready in order
    to allow for single unit deployments.

    @returns boolean
    """
    min_size = config('min-cluster-size')
    units = 1
    for relation_id in relation_ids('cluster'):
        units += len(related_units(relation_id))
    if not min_size:
        min_size = units

    if not is_sufficient_peers():
        return False
    elif min_size > 1:
        uuids = []
        for relation_id in relation_ids('cluster'):
            units = related_units(relation_id) or []
            units.append(local_unit())
            for unit in units:
                if not relation_get(attribute='bootstrap-uuid',
                                    rid=relation_id,
                                    unit=unit):
                    log("{} is not yet clustered".format(unit),
                        DEBUG)
                    return False
                else:
                    bootstrap_uuid = relation_get(attribute='bootstrap-uuid',
                                                  rid=relation_id,
                                                  unit=unit)
                    if bootstrap_uuid:
                        uuids.append(bootstrap_uuid)

        if len(uuids) < min_size:
            log("Fewer than minimum cluster size:{} percona units reporting "
                "clustered".format(min_size),
                DEBUG)
            return False
        elif len(set(uuids)) > 1:
            raise Exception("Found inconsistent bootstrap uuids - %s"
                            "".format((uuids)))
        else:
            log("All {} percona units reporting clustered"
                "".format(min_size),
                DEBUG)
            return True

    log("Must assume this is a single unit returning 'cluster' ready", DEBUG)
    return True


def client_node_is_ready():
    """Determine if the leader node has set shared-db client data

    @returns boolean
    """
    # Bail if this unit is paused
    if is_unit_paused_set():
        return False
    if not cluster_ready():
        return False
    for rid in relation_ids('shared-db'):
        if leader_get(attribute='{}_password'.format(rid)):
            return True
    return False


def leader_node_is_ready():
    """Determine if the leader node is ready to handle client relationship
    hooks.

    IFF percona is not paused, is installed, this is the leader node and the
    cluster is complete.

    @returns boolean
    """
    # Paused check must run before other checks
    # Bail if this unit is paused
    if is_unit_paused_set():
        return False
    return (is_leader() and cluster_ready())


def _get_password(key):
    '''Retrieve named password

    This function will ensure that a consistent named password
    is used across all units in the pxc cluster; the lead unit
    will generate or use the root-password configuration option
    to seed this value into the deployment.

    Once set, it cannot be changed.

    @requires: str: named password or None if unable to retrieve
                    at this point in time
    '''
    _password = leader_get(key)
    if not _password and is_leader():
        _password = config(key) or pwgen()
        leader_set({key: _password})
    return _password


root_password = partial(_get_password, 'root-password')

sst_password = partial(_get_password, 'sst-password')


def pxc_installed():
    '''Determine whether percona-xtradb-cluster is installed

    @returns: boolean: indicating installation
    '''
    return os.path.exists('/usr/sbin/mysqld')
