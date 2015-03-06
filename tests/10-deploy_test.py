#!/usr/bin/python3
# test percona-cluster (3 nodes)

import basic_deployment
import time


class ThreeNode(basic_deployment.BasicDeployment):
    def __init__(self):
        super(ThreeNode, self).__init__(units=3)

    def run(self):
        super(ThreeNode, self).run()
        # we are going to kill the master
        old_master = self.master_unit
        self.master_unit.run('sudo poweroff')

        time.sleep(10)  # give some time to pacemaker to react
        new_master = self.find_master()
        assert new_master is not None, "master unit not found"
        assert (new_master.info['public-address'] !=
                    old_master.info['public-address'])

        assert self.is_port_open(address=self.vip), 'cannot connect to vip'


if __name__ == "__main__":
    t = ThreeNode()
    t.run()
