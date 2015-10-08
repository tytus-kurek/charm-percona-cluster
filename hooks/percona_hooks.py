#!/usr/bin/python
# TODO: Support changes to root and sstuser passwords
import sys
import json
import os
import socket
import time

from charmhelpers.core.hookenv import (
    Hooks, UnregisteredHookError,
    is_relation_made,
    log,
    local_unit,
    relation_get,
    relation_set,
    relation_id,
    relation_ids,
    related_units,
    unit_get,
    config,
    remote_unit,
    relation_type,
    DEBUG,
    INFO,
    WARNING,
    is_leader,
    status_set,
)
from charmhelpers.core.host import (
    service,
    service_restart,
    service_start,
    file_hash,
    lsb_release,
)
from charmhelpers.core.templating import render
from charmhelpers.fetch import (
    apt_update,
    apt_install,
    add_source,
)
from charmhelpers.contrib.peerstorage import (
    peer_echo,
    peer_store_and_set,
    peer_retrieve_by_prefix,
)
from percona_utils import (
    determine_packages,
    MY_CNF,
    setup_percona_repo,
    get_host_ip,
    get_cluster_hosts,
    configure_sstuser,
    configure_mysql_root_password,
    relation_clear,
    assert_charm_supports_ipv6,
    unit_sorted,
    get_db_helper,
    mark_seeded, seeded,
    install_mysql_ocf,
    is_sufficient_peers,
    notify_bootstrapped,
    is_bootstrapped,
    get_wsrep_value,
    cluster_in_sync,
)
from charmhelpers.contrib.database.mysql import (
    PerconaClusterHelper,
)
from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    is_clustered,
    oldest_peer,
    DC_RESOURCE_NAME,
    peer_units,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_iface_for_address,
    get_netmask_for_address,
    get_ipv6_addr,
    is_address_in_network,
)

from charmhelpers.contrib.charmsupport import nrpe

hooks = Hooks()

RES_MONITOR_PARAMS = ('params user="sstuser" password="%(sstpass)s" '
                      'pid="/var/run/mysqld/mysqld.pid" '
                      'socket="/var/run/mysqld/mysqld.sock" '
                      'max_slave_lag="5" '
                      'cluster_type="pxc" '
                      'op monitor interval="1s" timeout="30s" '
                      'OCF_CHECK_LEVEL="1"')


@hooks.hook('install.real')
def install():
    execd_preinstall()
    if config('source') is None and \
            lsb_release()['DISTRIB_CODENAME'] < 'trusty':
        setup_percona_repo()
    elif config('source') is not None:
        add_source(config('source'), config('key'))

    configure_mysql_root_password(config('root-password'))
    # Render base configuration (no cluster)
    render_config()
    apt_update(fatal=True)
    apt_install(determine_packages(), fatal=True)
    configure_sstuser(config('sst-password'))


def render_config(clustered=False, hosts=[]):
    if not os.path.exists(os.path.dirname(MY_CNF)):
        os.makedirs(os.path.dirname(MY_CNF))

    context = {
        'cluster_name': 'juju_cluster',
        'private_address': get_host_ip(),
        'clustered': clustered,
        'cluster_hosts': ",".join(hosts),
        'sst_method': 'xtrabackup',
        'sst_password': config('sst-password'),
        'innodb_file_per_table': config('innodb-file-per-table'),
        'table_open_cache': config('table-open-cache'),
        'lp1366997_workaround': config('lp1366997-workaround')
    }

    if config('prefer-ipv6'):
        # NOTE(hopem): this is a kludge to get percona working with ipv6.
        # See lp 1380747 for more info. This is intended as a stop gap until
        # percona package is fixed to support ipv6.
        context['bind_address'] = '::'
        context['wsrep_provider_options'] = 'gmcast.listen_addr=tcp://:::4567;'
        context['ipv6'] = True
    else:
        context['ipv6'] = False

    context.update(PerconaClusterHelper().parse_config())
    render(os.path.basename(MY_CNF), MY_CNF, context, perms=0o444)


def render_config_restart_on_changed(clustered, hosts, bootstrap=False):
    """Render mysql config and restart mysql service if file changes as a
    result.

    If bootstrap is True we do a bootstrap-pxc in order to bootstrap the
    percona cluster. This should only be performed once at cluster creation
    time.

    If percona is already bootstrapped we can get away with just ensuring that
    it is started so long as the new node to be added is guaranteed to have
    been restarted so as to apply the new config.
    """
    pre_hash = file_hash(MY_CNF)
    render_config(clustered, hosts)
    update_db_rels = False
    if file_hash(MY_CNF) != pre_hash or bootstrap:
        if bootstrap:
            service('bootstrap-pxc', 'mysql')
            # NOTE(dosaboy): this will not actually do anything if no cluster
            # relation id exists yet.
            notify_bootstrapped()
            update_db_rels = True
        else:
            delay = 1
            attempts = 0
            max_retries = 5
            # NOTE(dosaboy): avoid unnecessary restarts. Once mysql is started
            # it needn't be restarted when new units join the cluster since the
            # new units will join and apply their own config.
            if not seeded():
                action = service_restart
            else:
                action = service_start

            while not action('mysql'):
                if attempts == max_retries:
                    raise Exception("Failed to start mysql (max retries "
                                    "reached)")

                log("Failed to start mysql - retrying in %ss" % (delay),
                    WARNING)
                time.sleep(delay)
                delay += 2
                attempts += 1

        # If we get here we assume prior actions have succeeded to always
        # this unit is marked as seeded so that subsequent calls don't result
        # in a restart.
        mark_seeded()

        if update_db_rels:
            update_shared_db_rels()
    else:
        log("Config file '%s' unchanged", level=DEBUG)


def update_shared_db_rels():
    for r_id in relation_ids('shared-db'):
        for unit in related_units(r_id):
            shared_db_changed(r_id, unit)


@hooks.hook('upgrade-charm')
def upgrade():
    check_bootstrap = False
    try:
        if is_leader():
            check_bootstrap = True
    except:
        if oldest_peer(peer_units()):
            check_bootstrap = True

    if check_bootstrap and not is_bootstrapped() and is_sufficient_peers():
        # If this is the leader but we have not yet broadcast the cluster uuid
        # then do so now.
        wsrep_ready = get_wsrep_value('wsrep_ready') or ""
        if wsrep_ready.lower() in ['on', 'ready']:
            cluster_state_uuid = get_wsrep_value('wsrep_cluster_state_uuid')
            if cluster_state_uuid:
                mark_seeded()
                notify_bootstrapped(cluster_uuid=cluster_state_uuid)

    config_changed()


@hooks.hook('config-changed')
def config_changed():
    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    hosts = get_cluster_hosts()
    clustered = len(hosts) > 1
    bootstrapped = is_bootstrapped()

    # NOTE: only configure the cluster if we have sufficient peers. This only
    # applies if min-cluster-size is provided and is used to avoid extraneous
    # configuration changes and premature bootstrapping as the cluster is
    # deployed.
    if is_sufficient_peers():
        try:
            # NOTE(jamespage): try with leadership election
            if is_leader():
                log("Leader unit - bootstrap required=%s" % (not bootstrapped),
                    DEBUG)
                render_config_restart_on_changed(clustered, hosts,
                                                 bootstrap=not bootstrapped)
            elif bootstrapped:
                log("Cluster is bootstrapped - configuring mysql on this node",
                    DEBUG)
                render_config_restart_on_changed(clustered, hosts)
            else:
                log("Not configuring", DEBUG)

        except NotImplementedError:
            # NOTE(jamespage): fallback to legacy behaviour.
            oldest = oldest_peer(peer_units())
            if oldest:
                log("Leader unit - bootstrap required=%s" % (not bootstrapped),
                    DEBUG)
                render_config_restart_on_changed(clustered, hosts,
                                                 bootstrap=not bootstrapped)
            elif bootstrapped:
                log("Cluster is bootstrapped - configuring mysql on this node",
                    DEBUG)
                render_config_restart_on_changed(clustered, hosts)
            else:
                log("Not configuring", DEBUG)

    # Notify any changes to the access network
    update_shared_db_rels()

    # (re)install pcmkr agent
    install_mysql_ocf()

    if relation_ids('ha'):
        # make sure all the HA resources are (re)created
        ha_relation_joined()

    if is_relation_made('nrpe-external-master'):
        update_nrpe_config()


@hooks.hook('cluster-relation-joined')
def cluster_joined():
    if config('prefer-ipv6'):
        addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_settings = {'private-address': addr,
                             'hostname': socket.gethostname()}
        log("Setting cluster relation: '%s'" % (relation_settings),
            level=INFO)
        relation_set(relation_settings=relation_settings)

    # Ensure all new peers are aware
    cluster_state_uuid = relation_get('bootstrap-uuid', unit=local_unit())
    if cluster_state_uuid:
        notify_bootstrapped(cluster_rid=relation_id(),
                            cluster_uuid=cluster_state_uuid)


@hooks.hook('cluster-relation-departed')
@hooks.hook('cluster-relation-changed')
def cluster_changed():
    # Need to make sure hostname is excluded to build inclusion list (paying
    # attention to those excluded by default in peer_echo().
    # TODO(dosaboy): extend peer_echo() to support providing exclusion list as
    #                well as inclusion list.
    # NOTE(jamespage): deprecated - leader-election
    rdata = relation_get()
    inc_list = []
    for attr in rdata.iterkeys():
        if attr not in ['hostname', 'private-address', 'public-address']:
            inc_list.append(attr)
    peer_echo(includes=inc_list)
    # NOTE(jamespage): deprecated - leader-election

    config_changed()


# TODO: This could be a hook common between mysql and percona-cluster
@hooks.hook('db-relation-changed')
@hooks.hook('db-admin-relation-changed')
def db_changed(relation_id=None, unit=None, admin=None):
    if not is_elected_leader(DC_RESOURCE_NAME):
        log('Service is peered, clearing db relation'
            ' as this service unit is not the leader')
        relation_clear(relation_id)
        return

    if is_clustered():
        db_host = config('vip')
    else:
        if config('prefer-ipv6'):
            db_host = get_ipv6_addr(exc_list=[config('vip')])[0]
        else:
            db_host = unit_get('private-address')

    if admin not in [True, False]:
        admin = relation_type() == 'db-admin'
    db_name, _ = remote_unit().split("/")
    username = db_name
    db_helper = get_db_helper()
    addr = relation_get('private-address', unit=unit, rid=relation_id)
    password = db_helper.configure_db(addr, db_name, username, admin=admin)

    relation_set(relation_id=relation_id,
                 relation_settings={
                     'user': username,
                     'password': password,
                     'host': db_host,
                     'database': db_name,
                 })


def get_db_host(client_hostname):
    vips = config('vip').split() if config('vip') else []
    client_ip = get_host_ip(client_hostname)
    access_network = config('access-network')
    if (access_network is not None and
            is_address_in_network(access_network, client_ip)):
        if is_clustered():
            for vip in vips:
                if is_address_in_network(access_network, vip):
                    return vip
        else:
            return get_address_in_network(access_network)
    elif is_clustered():
        return config('vip')  # NOTE on private network
    else:
        if config('prefer-ipv6'):
            return get_ipv6_addr(exc_list=vips)[0]
        else:
            return unit_get('private-address')


def configure_db_for_hosts(hosts, database, username, db_helper):
    """Hosts may be a json-encoded list of hosts or a single hostname."""
    try:
        hosts = json.loads(hosts)
        log("Multiple hostnames provided by relation: %s" % (', '.join(hosts)),
            level=DEBUG)
    except ValueError:
        log("Single hostname provided by relation: %s" % (hosts),
            level=DEBUG)
        hosts = [hosts]

    for host in hosts:
        password = db_helper.configure_db(host, database, username)

    return password


# TODO: This could be a hook common between mysql and percona-cluster
@hooks.hook('shared-db-relation-changed')
def shared_db_changed(relation_id=None, unit=None):
    if not seeded():
        log("Percona cluster not yet bootstrapped - deferring shared-db rel "
            "until bootstrapped", DEBUG)
        return

    if not is_elected_leader(DC_RESOURCE_NAME):
        # NOTE(jamespage): relation level data candidate
        log('Service is peered, clearing shared-db relation '
            'as this service unit is not the leader')
        relation_clear(relation_id)
        # Each unit needs to set the db information otherwise if the unit
        # with the info dies the settings die with it Bug# 1355848
        if is_relation_made('cluster'):
            for rel_id in relation_ids('shared-db'):
                peerdb_settings = \
                    peer_retrieve_by_prefix(rel_id, exc_list=['hostname'])

                passwords = [key for key in peerdb_settings.keys()
                             if 'password' in key.lower()]
                if len(passwords) > 0:
                    relation_set(relation_id=rel_id, **peerdb_settings)
        return

    settings = relation_get(unit=unit, rid=relation_id)
    if is_clustered():
        db_host = config('vip')
    else:
        if config('prefer-ipv6'):
            db_host = get_ipv6_addr(exc_list=[config('vip')])[0]
        else:
            db_host = unit_get('private-address')

    access_network = config('access-network')
    db_helper = get_db_helper()

    peer_store_and_set(relation_id=relation_id,
                       relation_settings={'access-network': access_network})

    singleset = set(['database', 'username', 'hostname'])
    if singleset.issubset(settings):
        # Process a single database configuration
        hostname = settings['hostname']
        database = settings['database']
        username = settings['username']

        normalized_address = get_host_ip(hostname)
        if access_network and not is_address_in_network(access_network,
                                                        normalized_address):
            # NOTE: for configurations using access-network, only setup
            #       database access if remote unit has presented a
            #       hostname or ip address thats within the configured
            #       network cidr
            return

        # NOTE: do this before querying access grants
        password = configure_db_for_hosts(hostname, database, username,
                                          db_helper)

        allowed_units = db_helper.get_allowed_units(database, username,
                                                    relation_id=relation_id)
        allowed_units = unit_sorted(allowed_units)
        allowed_units = ' '.join(allowed_units)
        relation_set(relation_id=relation_id, allowed_units=allowed_units)

        db_host = get_db_host(hostname)
        peer_store_and_set(relation_id=relation_id,
                           db_host=db_host,
                           password=password)
    else:
        # Process multiple database setup requests.
        # from incoming relation data:
        #  nova_database=xxx nova_username=xxx nova_hostname=xxx
        #  quantum_database=xxx quantum_username=xxx quantum_hostname=xxx
        # create
        # {
        #   "nova": {
        #        "username": xxx,
        #        "database": xxx,
        #        "hostname": xxx
        #    },
        #    "quantum": {
        #        "username": xxx,
        #        "database": xxx,
        #        "hostname": xxx
        #    }
        # }
        #
        databases = {}
        for k, v in settings.iteritems():
            db = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if db not in databases:
                databases[db] = {}
            databases[db][x] = v

        allowed_units = {}
        return_data = {}
        for db in databases:
            if singleset.issubset(databases[db]):
                database = databases[db]['database']
                hostname = databases[db]['hostname']
                username = databases[db]['username']

                normalized_address = get_host_ip(hostname)
                if (access_network and
                        not is_address_in_network(access_network,
                                                  normalized_address)):
                    # NOTE: for configurations using access-network,
                    #       only setup database access if remote unit
                    #       has presented a hostname or ip address
                    #       thats within the configured network cidr
                    return

                # NOTE: do this before querying access grants
                password = configure_db_for_hosts(hostname, database, username,
                                                  db_helper)

                a_units = db_helper.get_allowed_units(database, username,
                                                      relation_id=relation_id)
                a_units = ' '.join(unit_sorted(a_units))
                allowed_units['%s_allowed_units' % (db)] = a_units

                return_data['%s_password' % (db)] = password
                db_host = get_db_host(hostname)

        if allowed_units:
            relation_set(relation_id=relation_id, **allowed_units)
        else:
            log("No allowed_units - not setting relation settings",
                level=DEBUG)

        if return_data:
            peer_store_and_set(relation_id=relation_id, db_host=db_host,
                               **return_data)
        else:
            log("No return data - not setting relation settings", level=DEBUG)


@hooks.hook('ha-relation-joined')
def ha_relation_joined():
    vip = config('vip')
    vip_iface = get_iface_for_address(vip) or config('vip_iface')
    vip_cidr = get_netmask_for_address(vip) or config('vip_cidr')
    corosync_bindiface = config('ha-bindiface')
    corosync_mcastport = config('ha-mcastport')

    if None in [vip, vip_cidr, vip_iface]:
        log('Insufficient VIP information to configure cluster')
        sys.exit(1)

    if config('prefer-ipv6'):
        res_mysql_vip = 'ocf:heartbeat:IPv6addr'
        vip_params = 'params ipv6addr="%s" cidr_netmask="%s" nic="%s"' % \
                     (vip, vip_cidr, vip_iface)
    else:
        res_mysql_vip = 'ocf:heartbeat:IPaddr2'
        vip_params = 'params ip="%s" cidr_netmask="%s" nic="%s"' % \
                     (vip, vip_cidr, vip_iface)

    resources = {'res_mysql_vip': res_mysql_vip,
                 'res_mysql_monitor': 'ocf:percona:mysql_monitor'}

    sstpsswd = config('sst-password')
    resource_params = {'res_mysql_vip': vip_params,
                       'res_mysql_monitor':
                       RES_MONITOR_PARAMS % {'sstpass': sstpsswd}}
    groups = {'grp_percona_cluster': 'res_mysql_vip'}

    clones = {'cl_mysql_monitor': 'res_mysql_monitor meta interleave=true'}

    colocations = {'vip_mysqld': 'inf: grp_percona_cluster cl_mysql_monitor'}

    locations = {'loc_percona_cluster':
                 'grp_percona_cluster rule inf: writable eq 1'}

    for rel_id in relation_ids('ha'):
        relation_set(relation_id=rel_id,
                     corosync_bindiface=corosync_bindiface,
                     corosync_mcastport=corosync_mcastport,
                     resources=resources,
                     resource_params=resource_params,
                     groups=groups,
                     clones=clones,
                     colocations=colocations,
                     locations=locations)


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    clustered = relation_get('clustered')
    if (clustered and is_elected_leader(DC_RESOURCE_NAME)):
        log('Cluster configured, notifying other services')
        # Tell all related services to start using the VIP
        update_shared_db_rels()
        for r_id in relation_ids('db'):
            for unit in related_units(r_id):
                db_changed(r_id, unit, admin=False)
        for r_id in relation_ids('db-admin'):
            for unit in related_units(r_id):
                db_changed(r_id, unit, admin=True)


@hooks.hook('leader-settings-changed')
def leader_settings_changed():
    # Notify any changes to data in leader storage
    update_shared_db_rels()


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, 'mysql', current_unit)
    nrpe_setup.add_check(
        shortname='mysql_proc',
        description='Check MySQL process {%s}' % current_unit,
        check_cmd='check_procs -c 1:1 -C mysqld'
    )
    nrpe_setup.write()


def assess_status():
    '''Assess the status of the current unit'''
    # Ensure that number of peers > cluster size configuration
    if not is_bootstrapped():
        status_set('blocked', 'Insufficient peers to bootstrap cluster')
        return
    # Once running, ensure that cluster is in sync and has the required peers
    if is_bootstrapped() and cluster_in_sync():
        status_set('active', 'Unit is ready and in sync')
    else:
        status_set('blocked', 'Unit is not in sync')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status()


if __name__ == '__main__':
    main()
