import mock
import json
import unittest
import sys

sys.modules['MySQLdb'] = mock.Mock()
import mysql


class MysqlTests(unittest.TestCase):
    def setUp(self):
        super(MysqlTests, self).setUp()

    @mock.patch('mysql.get_mysql_root_password')
    @mock.patch('mysql.MySQLHelper', autospec=True)
    @mock.patch('mysql.relation_get')
    @mock.patch('mysql.related_units')
    @mock.patch('mysql.log')
    def test_get_allowed_units(self, mock_log, mock_related_units, 
                               mock_relation_get, mock_helper,
                               mock_get_password):

        def mock_rel_get(unit, rid):
            if unit == 'unit/0':
                # Non-prefixed settings
                d = {'private-address': '10.0.0.1',
                     'hostname': 'hostA'}
            elif unit == 'unit/1':
                # Containing prefixed settings
                d = {'private-address': '10.0.0.2',
                     'dbA_hostname': json.dumps(['10.0.0.2', '2001:db8:1::2'])}
            elif unit == 'unit/2':
                # No hostname
                d = {'private-address': '10.0.0.3'}

            return d

        mock_relation_get.side_effect = mock_rel_get
        mock_related_units.return_value = ['unit/0', 'unit/1', 'unit/2']

        units = mysql.get_allowed_units('dbA', 'userA')

        calls = [mock.call('dbA', 'userA', 'hostA'),
                 mock.call().__nonzero__(),
                 mock.call('dbA', 'userA', '10.0.0.2'),
                 mock.call().__nonzero__(),
                 mock.call('dbA', 'userA', '2001:db8:1::2'),
                 mock.call().__nonzero__(),
                 mock.call('dbA', 'userA', '10.0.0.3'),
                 mock.call().__nonzero__()]

        mock_helper.return_value.grant_exists.assert_has_calls(calls)
        self.assertEqual(units, set(['unit/0', 'unit/1', 'unit/2']))
