import amulet
import re
import os
import time
import telnetlib
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
        if units > 1:
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
                                    ("Please set the vip in local.yaml or "
                                     "env var AMULET_OS_VIP to run this test "
                                     "suite"))

    def _add_services(self):
        """Add services

           Add the services that we're testing, where percona-cluster is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'percona-cluster',
                        'units': self.units}
        other_services = []
        if self.units > 1:
            other_services.append({'name': 'hacluster'})

        super(BasicDeployment, self)._add_services(this_service,
                                                   other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        if self.units > 1:
            relations = {'percona-cluster:ha': 'hacluster:ha'}
            super(BasicDeployment, self)._add_relations(relations)

    def _get_configs(self):
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

        configs = {'percona-cluster': cfg_percona}
        if self.units > 1:
            configs['hacluster'] = cfg_ha

        return configs

    def _configure_services(self):
        super(BasicDeployment, self)._configure_services(self._get_configs())

    def run(self):
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()

        if self.units > 1:
            i = 0
            while i < 30 and not self.master_unit:
                self.master_unit = self.find_master()
                i += 1
                time.sleep(10)

            msg = 'percona-cluster vip not found'
            assert self.master_unit is not None, msg

            _, code = self.master_unit.run('sudo crm_verify --live-check')
            assert code == 0, "'crm_verify --live-check' failed"

            resources = ['res_mysql_vip']
            resources += ['res_mysql_monitor:%d' %
                          m for m in range(self.units)]

            assert sorted(self.get_pcmkr_resources()) == sorted(resources)
        else:
            self.master_unit = self.find_master(ha=False)

        for unit in self.d.sentry['percona-cluster']:
            assert self.is_mysqld_running(unit), 'mysql not running: %s' % unit

    def find_master(self, ha=True):
        for unit in self.d.sentry['percona-cluster']:
            if not ha:
                return unit

            # is the vip running here?
            output, code = unit.run('sudo ip a | grep "inet %s/"' % self.vip)
            print('---')
            print(unit)
            print(output)
            if code == 0:
                print('vip(%s) running in %s' % (self.vip, unit))
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

        _, code = u.run('pidof mysqld')
        if code != 0:
            print("ERROR: command returned non-zero '%s'" % (code))
            return False

        return True

    def get_wsrep_value(self, attr, unit=None):
        if unit:
            u = unit
        else:
            u = self.master_unit

        cmd = ("mysql -uroot -pt00r -e\"show status like '%s';\"| "
               "grep %s" % (attr, attr))
        output, code = u.run(cmd)
        if code != 0:
            print("ERROR: command returned non-zero '%s'" % (code))
            return ""

        value = re.search(r"^.+?\s+(.+)", output).group(1)
        print("%s = %s" % (attr, value))
        return value

    def is_pxc_bootstrapped(self, unit=None):
        value = self.get_wsrep_value('wsrep_ready', unit)
        return value.lower() in ['on', 'ready']

    def get_cluster_size(self, unit=None):
        return self.get_wsrep_value('wsrep_cluster_size', unit)

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
            print("ERROR: could not connect to %s:%s" % (addr, port))
            return False
        except ConnectionRefusedError:  # noqa - also only in py3
            print("ERROR: connection refused connecting to %s:%s" % (addr,
                                                                     port))
            return False
