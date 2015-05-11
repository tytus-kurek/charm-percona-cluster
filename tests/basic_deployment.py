import amulet
import os
import time
import telnetlib
import unittest
import yaml
from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)


class BasicDeployment(OpenStackAmuletDeployment):
    def __init__(self, vip=None, units=1, series="trusty", openstack=None,
                 source=None, stable=False):
        super(BasicDeployment, self).__init__(series, openstack, source,
                                              stable)
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

    def _add_services(self):
        """Add services

           Add the services that we're testing, where percona-cluster is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'percona-cluster',
                        'units': self.units}
        other_services = [{'name': 'hacluster'}]
        super(BasicDeployment, self)._add_services(this_service,
                                                   other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {'percona-cluster:ha': 'hacluster:ha'}
        super(BasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        cfg_percona = {'sst-password': 'ubuntu',
                       'root-password': 't00r',
                       'dataset-size': '512M',
                       'vip': self.vip}

        cfg_ha = {'debug': True,
                  'corosync_mcastaddr': '226.94.1.4',
                  'corosync_key': ('xZP7GDWV0e8Qs0GxWThXirNNYlScgi3sRTdZk/IXKD'
                                   'qkNFcwdCWfRQnqrHU/6mb6sz6OIoZzX2MtfMQIDcXu'
                                   'PqQyvKuv7YbRyGHmQwAWDUA4ed759VWAO39kHkfWp9'
                                   'y5RRk/wcHakTcWYMwm70upDGJEP00YT3xem3NQy27A'
                                   'C1w=')}

        configs = {'percona-cluster': cfg_percona,
                   'hacluster': cfg_ha}
        super(BasicDeployment, self)._configure_services(configs)

    def run(self):
        # The number of seconds to wait for the environment to setup.
        seconds = 1200

        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()

        i = 0
        while i < 30 and not self.master_unit:
            self.master_unit = self.find_master()
            i += 1
            time.sleep(10)

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
            output, code = unit.run('sudo ip a | grep "inet %s/"' % self.vip)
            print('---')
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
