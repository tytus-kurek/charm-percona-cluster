import amulet
import os
import telnetlib
import unittest
import yaml


class BasicDeployment(unittest.TestCase):
    def __init__(self, vip=None, units=1):
        self.units = units
        self.master_unit = None
        self.vip = None
        if vip:
            self.vip = vip
        elif 'AMULET_OS_VIP' in os.environ:
            self.vip = os.environ.get('AMULET_OS_VIP')
        elif os.path.isfile('local.yaml'):
            with open('local.yaml', 'rb') as f:
                self.cfg = yaml.safe_load(f.read())

            self.vip = self.cfg.get('vip')
        else:
            amulet.raise_status(amulet.SKIP,
                                ("please set the vip in local.yaml or env var "
                                 "AMULET_OS_VIP to run this test suite"))

    def run(self):
        # The number of seconds to wait for the environment to setup.
        seconds = 1200

        self.d = amulet.Deployment(series="trusty")
        self.d.add('percona-cluster', units=self.units)

        # NOTE(freyes): we use hacluster/next, because stable doesn't support
        # location rules definition.
        self.d.add('hacluster',
                   charm='lp:~openstack-charmers/charms/trusty/hacluster/next')
        self.d.relate('percona-cluster:ha', 'hacluster:ha')

        cfg_percona = {'sst-password': 'ubuntu',
                       'root-password': 't00r',
                       'dataset-size': '128M',
                       'vip': self.vip}

        cfg_ha = {'debug': True,
                  'corosync_mcastaddr': '226.94.1.4',
                  'corosync_key': ('xZP7GDWV0e8Qs0GxWThXirNNYlScgi3sRTdZk/IXKD'
                                   'qkNFcwdCWfRQnqrHU/6mb6sz6OIoZzX2MtfMQIDcXu'
                                   'PqQyvKuv7YbRyGHmQwAWDUA4ed759VWAO39kHkfWp9'
                                   'y5RRk/wcHakTcWYMwm70upDGJEP00YT3xem3NQy27A'
                                   'C1w=')}

        self.d.configure('percona-cluster', cfg_percona)
        self.d.configure('hacluster', cfg_ha)

        try:
            self.d.setup(timeout=seconds)
            self.d.sentry.wait(seconds)
        except amulet.helpers.TimeoutError:
            message = 'The environment did not setup in %d seconds.' % seconds
            amulet.raise_status(amulet.SKIP, msg=message)
        except:
            raise

        self.master_unit = self.find_master()
        assert self.master_unit is not None, 'percona-cluster vip not found'

        output, code = self.master_unit.run('sudo crm_verify --live-check')
        assert code == 0, "'crm_verify --live-check' failed"

        resources = ['res_mysql_vip']
        resources += ['res_mysql_monitor:%d' % i for i in range(self.units)]

        assert sorted(self.get_pcmkr_resources()) == sorted(resources)

        for i in range(self.units):
            uid = 'percona-cluster/%d' % i
            unit = self.d.sentry.unit[uid]
            assert self.is_mysqld_running(unit), 'mysql not running: %s' % uid

    def find_master(self):
        for unit_id, unit in self.d.sentry.unit.items():
            if not unit_id.startswith('percona-cluster/'):
                continue

            # is the vip running here?
            output, code = unit.run('sudo ip a | grep %s' % self.vip)
            print(unit_id)
            print(output)
            if code == 0:
                print('vip(%s) running in %s' % (self.vip, unit_id))
                return unit

    def get_pcmkr_resources(self, unit=None):
        if unit:
            u = unit
        else:
            u = self.master_unit

        output, code = u.run('sudo crm_resource -l')

        assert code == 0, 'could not get "crm resource list"'

        return output.split('\n')

    def is_mysqld_running(self, unit=None):
        if unit:
            u = unit
        else:
            u = self.master_unit

        output, code = u.run('pidof mysqld')

        if code != 0:
            return False

        return self.is_port_open(u, '3306')

    def is_port_open(self, unit=None, port='3306', address=None):
        if unit:
            addr = unit.info['public-address']
        elif address:
            addr = address
        else:
            raise Exception('Please provide a unit or address')
        try:
            telnetlib.Telnet(addr, port)
            return True
        except TimeoutError:  # noqa this exception only available in py3
            return False
