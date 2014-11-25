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
    @mock.patch('mysql.relation_ids')
    @mock.patch('mysql.log')
    def test_get_allowed_units(self, mock_log, mock_relation_ids,
                               mock_related_units, 
                               mock_relation_get, mock_helper,
                               mock_get_password):
        mock_relation_ids.return_value = ['r1']
        mock_related_units.return_value = ['ru1', 'ru2']

        def mock_rel_get(attribute, unit, rid):
            if unit == 'ru2':
                d = {'private-address': '1.2.3.4',
                     'dbA_hostname': json.dumps(['2.3.4.5', '6.7.8.9'])}
            else:
                d = {'private-address': '1.2.3.4'}

            return d.get(attribute, None)

        mock_relation_get.side_effect = mock_rel_get
        units = mysql.get_allowed_units('dbA', 'userA')
        mock_helper.return_value.grant_exists.assert_called_with('dbA',
                                                                 'userA',
                                                                 '6.7.8.9')
        self.assertEqual(units, set(['ru1', 'ru2']))
