#!/usr/bin/env python
# test percona-cluster (1 node)
import basic_deployment


class MultiNode(basic_deployment.BasicDeployment):
    def __init__(self):
        super(MultiNode, self).__init__(units=2)

    def _get_configs(self):
        """Configure all of the services."""
        cfg_percona = {'sst-password': 'ubuntu',
                       'root-password': 't00r',
                       'dataset-size': '512M',
                       'vip': self.vip,
                       'min-cluster-size': 3}

        cfg_ha = {'debug': True,
                  'corosync_mcastaddr': '226.94.1.4',
                  'corosync_key': ('xZP7GDWV0e8Qs0GxWThXirNNYlScgi3sRTdZk/IXKD'
                                   'qkNFcwdCWfRQnqrHU/6mb6sz6OIoZzX2MtfMQIDcXu'
                                   'PqQyvKuv7YbRyGHmQwAWDUA4ed759VWAO39kHkfWp9'
                                   'y5RRk/wcHakTcWYMwm70upDGJEP00YT3xem3NQy27A'
                                   'C1w=')}

        configs = {'percona-cluster': cfg_percona}
        if self.units > 1:
            configs['hacluster'] = cfg_ha

        return configs

    def run(self):
        super(MultiNode, self).run()
        got = self.get_cluster_size()
        msg = "Percona cluster unexpected size (wanted=%s, got=%s)" % (1, got)
        assert got == '1', msg


if __name__ == "__main__":
    t = MultiNode()
    t.run()
