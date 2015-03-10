#!/usr/bin/python
# TODO: Support changes to root and sstuser passwords

import sys
import json
import os
import socket

from charmhelpers.core.hookenv import (
    Hooks, UnregisteredHookError,
    is_relation_made,
    log,
    relation_get,
    relation_set,
    relation_ids,
    related_units,
    unit_get,
    config,
    remote_unit,
    relation_type,
    DEBUG,
    INFO,
    ERROR,
    is_leader,
)
from charmhelpers.core.host import (
    service_restart,
    service_running,
    service,
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
    PACKAGES,
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
    mark_seeded, seeded
)
from charmhelpers.contrib.database.mysql import (
    PerconaClusterHelper,
)
from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    is_clustered,
    oldest_peer,
    peer_units,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_netmask_for_address,
    get_iface_for_address,
    get_ipv6_addr,
    is_address_in_network,
    is_ipv6,
)

hooks = Hooks()

LEADER_RES = 'grp_percona_cluster'


@hooks.hook('install')
def install():
    execd_preinstall()
    if config('source') is None and \
            lsb_release()['DISTRIB_CODENAME'] < 'trusty':
        setup_percona_repo()
    elif config('source') is not None:
        add_source(config('source'))

    configure_mysql_root_password(config('root-password'))
    db_helper = get_db_helper()
    cfg_passwd = config('sst-password')
    mysql_password = db_helper.get_mysql_password(username='sstuser',
                                                  password=cfg_passwd)
    # Render base configuration (no cluster)
    render_config(mysql_password=mysql_password)
    apt_update(fatal=True)
    apt_install(PACKAGES, fatal=True)
    configure_sstuser(mysql_password)


def render_config(clustered=False, hosts=[], mysql_password=None):
    if not os.path.exists(os.path.dirname(MY_CNF)):
        os.makedirs(os.path.dirname(MY_CNF))

    if not mysql_password:
        db_helper = get_db_helper()
        cfg_passwd = config('sst-password')
        mysql_password = db_helper.get_mysql_password(username='sstuser',
                                                      password=cfg_passwd)

    context = {
        'cluster_name': 'juju_cluster',
        'private_address': get_host_ip(),
        'clustered': clustered,
        'cluster_hosts': ",".join(hosts),
        'sst_method': 'xtrabackup',
        'sst_password': mysql_password,
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


@hooks.hook('upgrade-charm')
@hooks.hook('config-changed')
def config_changed():
    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    hosts = get_cluster_hosts()
    clustered = len(hosts) > 1
    pre_hash = file_hash(MY_CNF)
    render_config(clustered, hosts)
    if file_hash(MY_CNF) != pre_hash:
        try:
            # NOTE(jamespage): don't restart the leader as this
            # should be the source of initial syncs for pxc
            if not is_leader():
                # Bootstrap node into seeded cluster
                service_restart('mysql')
        except NotImplementedError:
            # NOTE(jamespage): fallback to legacy behaviour.
            oldest = oldest_peer(peer_units())
            if clustered and not oldest and not seeded():
                # Bootstrap node into seeded cluster
                service_restart('mysql')
                mark_seeded()
            elif not clustered:
                # Restart with new configuration
                service_restart('mysql')

    try:
        # NOTE(jamespage): this should deal with full outages
        # of PXC where all nodes have been shutdown.
        if is_leader() and not service_running('mysql'):
            service(service_name='mysql',
                    action='bootstrap-pxc')
    except NotImplementedError:
        log('Unable to automatically recover cluster, '
            'please perform manual recovery',
            level=ERROR)
        raise

    # Notify any changes to the access network
    for r_id in relation_ids('shared-db'):
        for unit in related_units(r_id):
            shared_db_changed(r_id, unit)


@hooks.hook('cluster-relation-joined')
def cluster_joined(relation_id=None):
    if config('prefer-ipv6'):
        addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_settings = {'private-address': addr,
                             'hostname': socket.gethostname()}
        log("Setting cluster relation: '%s'" % (relation_settings),
            level=INFO)
        relation_set(relation_id=relation_id,
                     relation_settings=relation_settings)


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
    if not is_elected_leader(LEADER_RES):
        log('Not leader of service, deferring db-changed to leader')
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
        return config('vip') # NOTE on private network
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
    if not is_elected_leader(LEADER_RES):
        # NOTE(jamespage): relation level data candidate
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

        log('Service is peered, clearing shared-db relation'
            ' as this service unit is not the leader')
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

    singleset = set(['database', 'username', 'hostname'])
    if singleset.issubset(settings):
        # Process a single database configuration
        hostname = settings['hostname']
        database = settings['database']
        username = settings['username']

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

    peer_store_and_set(relation_id=relation_id,
                       relation_settings={'access-network': access_network})


@hooks.hook('ha-relation-joined')
def ha_relation_joined(relation_id=None):
    vips = config('vip')
    if not vips:
        log('Insufficient VIP information to configure cluster')
        sys.exit(1)

    corosync_bindiface = config('ha-bindiface')
    corosync_mcastport = config('ha-mcastport')
    resources = {}
    resource_params = {}

    vip_group = []
    for vip in vips.split():
        if is_ipv6(vip):
            res_ks_vip = 'ocf:heartbeat:IPv6addr'
            vip_params = 'ipv6addr'
        else:
            res_ks_vip = 'ocf:heartbeat:IPaddr2'
            vip_params = 'ip'

        iface = (get_iface_for_address(vip) or
                 config('vip_iface'))
        netmask = (get_netmask_for_address(vip) or
                   config('vip_cidr'))

        if iface is not None:
            vip_key = 'res_mysql_{}_vip'.format(iface)
            resources[vip_key] = res_ks_vip
            resource_params[vip_key] = (
                'params {ip}="{vip}" cidr_netmask="{netmask}"'
                ' nic="{iface}"'.format(ip=vip_params,
                                        vip=vip,
                                        iface=iface,
                                        netmask=netmask)
            )
            vip_group.append(vip_key)

    groups = None
    if len(vip_group) >= 1:
        groups = {'grp_percona_cluster': ' '.join(vip_group)}
    else:
        log('Unable to configure/detect VIP configuration information')
        sys.exit(1)

    for rel_id in relation_ids('ha'):
        relation_set(relation_id=rel_id,
                     corosync_bindiface=corosync_bindiface,
                     corosync_mcastport=corosync_mcastport,
                     resources=resources,
                     resource_params=resource_params,
                     groups=groups)


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    clustered = relation_get('clustered')
    if (clustered and is_elected_leader(LEADER_RES)):
        log('Cluster configured, notifying other services')
        # Tell all related services to start using the VIP
        for r_id in relation_ids('shared-db'):
            for unit in related_units(r_id):
                shared_db_changed(r_id, unit)
        for r_id in relation_ids('db'):
            for unit in related_units(r_id):
                db_changed(r_id, unit, admin=False)
        for r_id in relation_ids('db-admin'):
            for unit in related_units(r_id):
                db_changed(r_id, unit, admin=True)


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
