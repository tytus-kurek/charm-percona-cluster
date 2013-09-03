#!/usr/bin/python

import sys
import os
from charmhelpers.core.hookenv import (
    Hooks, UnregisteredHookError,
    log
)
from charmhelpers.core.host import (
    restart_on_change
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
    configure_sstuser
)
from charmhelpers.contrib.hahelpers.cluster import (
    peer_units,
    oldest_peer
)

hooks = Hooks()


@hooks.hook('install')
def install():
    setup_percona_repo()
    apt_update(fatal=True)
    apt_install(PACKAGES, fatal=True)
    configure_sstuser()


@hooks.hook('cluster-relation-changed')
@hooks.hook('upgrade-charm')
@hooks.hook('config-changed')
@restart_on_change({MY_CNF: ['mysql']})
def cluster_changed():
    hosts = get_cluster_hosts()
    clustered = False
    if len(hosts) > 1:
        clustered = True
    with open(MY_CNF, 'w') as conf:
        conf.write(render_template(os.path.basename(MY_CNF),
                                   {'cluster_name': 'juju_cluster',
                                    'private_address': get_host_ip(),
                                    'clustered': clustered,
                                    'cluster_hosts': ",".join(hosts)}
                                   )
                   )
    # This is horrid but stops the bootstrap node
    # restarting itself when new nodes start joining
    if clustered and oldest_peer(peer_units()):
        sys.exit(0)


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
