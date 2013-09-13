#!/usr/bin/python
# TODO: sync passwd files from seed to peers

import sys
import os
from charmhelpers.core.hookenv import (
    Hooks, UnregisteredHookError,
    log,
    relation_get,
    relation_set,
    relation_ids,
    unit_get,
    config
)
from charmhelpers.core.host import (
    service_restart,
    file_hash
)
from charmhelpers.fetch import (
    apt_update,
    apt_install,
)
from percona_utils import (
    PACKAGES,
    MY_CNF,
    setup_percona_repo,
    render_template,
    get_host_ip,
    get_cluster_hosts,
    configure_sstuser,
    seeded, mark_seeded,
    configure_mysql_root_password
)
from charmhelpers.contrib.hahelpers.cluster import (
    peer_units,
    oldest_peer,
    eligible_leader,
    is_clustered,
    is_leader
)
from mysql import configure_db

hooks = Hooks()


@hooks.hook('install')
def install():
    setup_percona_repo()
    configure_mysql_root_password()
    render_config()  # Render base configuation no cluster
    apt_update(fatal=True)
    apt_install(PACKAGES, fatal=True)
    configure_sstuser()


def render_config(clustered=False, hosts=[]):
    if not os.path.exists(os.path.dirname(MY_CNF)):
        os.makedirs(os.path.dirname(MY_CNF))
    with open(MY_CNF, 'w') as conf:
        conf.write(render_template(os.path.basename(MY_CNF),
                                   {'cluster_name': 'juju_cluster',
                                    'private_address': get_host_ip(),
                                    'clustered': clustered,
                                    'cluster_hosts': ",".join(hosts)}
                                   )
                   )


@hooks.hook('cluster-relation-changed')
@hooks.hook('upgrade-charm')
@hooks.hook('config-changed')
def cluster_changed():
    hosts = get_cluster_hosts()
    clustered = len(hosts) > 1
    pre_hash = file_hash(MY_CNF)
    render_config(clustered, hosts)
    if file_hash(MY_CNF) != pre_hash:
        oldest = oldest_peer(peer_units())
        if clustered and not oldest and not seeded():
            # Bootstrap node into seeded cluster
            service_restart('mysql')
            mark_seeded()
        elif not clustered:
            # Restart with new configuration
            service_restart('mysql')

LEADER_RES = 'res_mysql_vip'


@hooks.hook('shared-db-relation-changed')
def shared_db_changed():
    if not eligible_leader(LEADER_RES):
        log('MySQL service is peered, bailing shared-db relation'
            ' as this service unit is not the leader')
        return

    settings = relation_get()
    if is_clustered():
        db_host = config('vip')
    else:
        db_host = unit_get('private-address')
    singleset = set([
        'database',
        'username',
        'hostname'
    ])

    if singleset.issubset(settings):
        # Process a single database configuration
        password = configure_db(settings['hostname'],
                                settings['database'],
                                settings['username'])
        relation_set(db_host=db_host,
                     password=password)
    else:
        # Process multiple database setup requests.
        # from incoming relation data:
        #  nova_database=xxx nova_username=xxx nova_hostname=xxx
        #  quantum_database=xxx quantum_username=xxx quantum_hostname=xxx
        # create
        #{
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
        #}
        #
        databases = {}
        for k, v in settings.iteritems():
            db = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if db not in databases:
                databases[db] = {}
            databases[db][x] = v
        return_data = {}
        for db in databases:
            if singleset.issubset(databases[db]):
                return_data['_'.join([db, 'password'])] = \
                    configure_db(databases[db]['hostname'],
                                 databases[db]['database'],
                                 databases[db]['username'])
        if len(return_data) > 0:
            relation_set(**return_data)
            relation_set(db_host=db_host)


@hooks.hook('ha-relation-joined')
def ha_relation_joined():
    vip = config('vip')
    vip_iface = config('vip_iface')
    vip_cidr = config('vip_cidr')
    corosync_bindiface = config('ha-bindiface')
    corosync_mcastport = config('ha-mcastport')

    if None in [vip, vip_cidr, vip_iface]:
        log('Insufficient VIP information to configure cluster')
        sys.exit(1)

    resources = {
        'res_mysql_vip': 'ocf:heartbeat:IPaddr2',
        }

    resource_params = {
        'res_mysql_vip': 'params ip="%s" cidr_netmask="%s" nic="%s"' % \
                         (vip, vip_cidr, vip_iface),
        }

    groups = {
        'grp_percona_cluster': 'res_mysql_vip',
        }

    for rel_id in relation_ids('ha'):
        relation_set(rid=rel_id,
                     corosync_bindiface=corosync_bindiface,
                     corosync_mcastport=corosync_mcastport,
                     resources=resources,
                     resource_params=resource_params,
                     groups=groups)


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    clustered = relation_get('clustered')
    if (clustered and is_leader(LEADER_RES)):
        log('Cluster configured, notifying other services')
        # Tell all related services to start using the VIP
        for r_id in relation_ids('shared-db'):
            relation_set(rid=r_id,
                         db_host=config('vip'))
    else:
        # TODO: Unset any data already set if not leader
        pass


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
