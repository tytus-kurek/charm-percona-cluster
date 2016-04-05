#!/usr/bin/env python
# test percona-cluster (1 node) with pause and resume.

from charmhelpers.contrib.openstack.amulet.utils import (  # noqa
    OpenStackAmuletUtils,
    DEBUG,
    # ERROR
    )

import basic_deployment


u = OpenStackAmuletUtils(DEBUG)


class SingleNode(basic_deployment.BasicDeployment):
    def __init__(self):
        super(SingleNode, self).__init__(units=1)

    def run(self):
        super(SingleNode, self).run()
        assert self.is_pxc_bootstrapped(), "Cluster not bootstrapped"
        sentry_unit = self.d.sentry.unit['percona-cluster/0']

        assert u.status_get(sentry_unit)[0] == "active"

        action_id = u.run_action(sentry_unit, "pause")
        assert u.wait_on_action(action_id), "Pause action failed."
        assert u.status_get(sentry_unit)[0] == "maintenance"

        action_id = u.run_action(sentry_unit, "resume")
        assert u.wait_on_action(action_id), "Resume action failed."
        assert u.status_get(sentry_unit)[0] == "active"
        u.log.debug('OK')


if __name__ == "__main__":
    t = SingleNode()
    t.run()
