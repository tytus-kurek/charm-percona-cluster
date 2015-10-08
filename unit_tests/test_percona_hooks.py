import mock
import sys
from test_utils import CharmTestCase

sys.modules['MySQLdb'] = mock.Mock()
import percona_hooks as hooks

TO_PATCH = ['log', 'config',
            'get_db_helper',
            'relation_ids',
            'relation_set',
            'update_nrpe_config',
            'get_iface_for_address',
            'get_netmask_for_address',
            'cluster_in_sync',
            'is_bootstrapped',
            'status_set']


class TestHaRelation(CharmTestCase):
    def setUp(self):
        CharmTestCase.setUp(self, hooks, TO_PATCH)

    @mock.patch('sys.exit')
    def test_relation_not_configured(self, exit_):
        self.config.return_value = None

        class MyError(Exception):
            pass

        def f(x):
            raise MyError(x)
        exit_.side_effect = f
        self.assertRaises(MyError, hooks.ha_relation_joined)

    def test_resources(self):
        self.relation_ids.return_value = ['ha:1']
        password = 'ubuntu'
        helper = mock.Mock()
        attrs = {'get_mysql_password.return_value': password}
        helper.configure_mock(**attrs)
        self.get_db_helper.return_value = helper
        self.get_netmask_for_address.return_value = None
        self.get_iface_for_address.return_value = None
        self.test_config.set('vip', '10.0.3.3')
        self.test_config.set('sst-password', password)

        def f(k):
            return self.test_config.get(k)

        self.config.side_effect = f
        hooks.ha_relation_joined()

        resources = {'res_mysql_vip': 'ocf:heartbeat:IPaddr2',
                     'res_mysql_monitor': 'ocf:percona:mysql_monitor'}
        resource_params = {'res_mysql_vip': ('params ip="10.0.3.3" '
                                             'cidr_netmask="24" '
                                             'nic="eth0"'),
                           'res_mysql_monitor':
                           hooks.RES_MONITOR_PARAMS % {'sstpass': 'ubuntu'}}
        groups = {'grp_percona_cluster': 'res_mysql_vip'}

        clones = {'cl_mysql_monitor': 'res_mysql_monitor meta interleave=true'}

        colocations = {'vip_mysqld': 'inf: grp_percona_cluster cl_mysql_monitor'}  # noqa

        locations = {'loc_percona_cluster':
                     'grp_percona_cluster rule inf: writable eq 1'}

        self.relation_set.assert_called_with(
            relation_id='ha:1', corosync_bindiface=f('ha-bindiface'),
            corosync_mcastport=f('ha-mcastport'), resources=resources,
            resource_params=resource_params, groups=groups,
            clones=clones, colocations=colocations, locations=locations)

    def test_resource_params_vip_cidr_iface_autodetection(self):
        """
        Auto-detected values for vip_cidr and vip_iface are used to configure
        VIPs, even when explicit config options are provided.
        """
        self.relation_ids.return_value = ['ha:1']
        helper = mock.Mock()
        self.get_db_helper.return_value = helper
        self.get_netmask_for_address.return_value = '20'
        self.get_iface_for_address.return_value = 'eth1'
        self.test_config.set('vip', '10.0.3.3')
        self.test_config.set('vip_cidr', '16')
        self.test_config.set('vip_iface', 'eth0')

        def f(k):
            return self.test_config.get(k)

        self.config.side_effect = f
        hooks.ha_relation_joined()

        resource_params = {'res_mysql_vip': ('params ip="10.0.3.3" '
                                             'cidr_netmask="20" '
                                             'nic="eth1"'),
                           'res_mysql_monitor':
                           hooks.RES_MONITOR_PARAMS % {'sstpass': 'None'}}

        call_args, call_kwargs = self.relation_set.call_args
        self.assertEqual(resource_params, call_kwargs['resource_params'])

    def test_resource_params_no_vip_cidr_iface_autodetection(self):
        """
        When autodetecting vip_cidr and vip_iface fails, values from
        vip_cidr and vip_iface config options are used instead.
        """
        self.relation_ids.return_value = ['ha:1']
        helper = mock.Mock()
        self.get_db_helper.return_value = helper
        self.get_netmask_for_address.return_value = None
        self.get_iface_for_address.return_value = None
        self.test_config.set('vip', '10.0.3.3')
        self.test_config.set('vip_cidr', '16')
        self.test_config.set('vip_iface', 'eth1')

        def f(k):
            return self.test_config.get(k)

        self.config.side_effect = f
        hooks.ha_relation_joined()

        resource_params = {'res_mysql_vip': ('params ip="10.0.3.3" '
                                             'cidr_netmask="16" '
                                             'nic="eth1"'),
                           'res_mysql_monitor':
                           hooks.RES_MONITOR_PARAMS % {'sstpass': 'None'}}

        call_args, call_kwargs = self.relation_set.call_args
        self.assertEqual(resource_params, call_kwargs['resource_params'])


class TestAssessStatus(CharmTestCase):
    def setUp(self):
        CharmTestCase.setUp(self, hooks, TO_PATCH)

    def test_not_bootstrapped(self):
        self.is_bootstrapped.return_value = False
        hooks.assess_status()
        self.status_set.assert_called_with('blocked', mock.ANY)

    def test_bootstrapped_in_sync(self):
        self.is_bootstrapped.return_value = True
        self.cluster_in_sync.return_value = True
        hooks.assess_status()
        self.status_set.assert_called_with('active', mock.ANY)

    def test_bootstrapped_not_in_sync(self):
        self.is_bootstrapped.return_value = True
        self.cluster_in_sync.return_value = False
        hooks.assess_status()
        self.status_set.assert_called_with('blocked', mock.ANY)
