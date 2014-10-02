import mock
import os
import unittest
import tempfile
import sys

sys.modules['MySQLdb'] = mock.Mock()
import percona_utils


class UtilsTests(unittest.TestCase):
    def setUp(self):
        super(UtilsTests, self).setUp()

    @mock.patch("percona_utils.log")
    def test_update_empty_hosts_file(self, mock_log):
        map = {'1.2.3.4': 'my-host'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            percona_utils.HOSTS_FILE = tmpfile.name
            percona_utils.HOSTS_FILE = tmpfile.name
            percona_utils.update_hosts_file(map)

        with open(tmpfile.name, 'r') as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "%s %s\n" % (map.items()[0]))

    @mock.patch("percona_utils.log")
    def test_update_hosts_file_w_dup(self, mock_log):
        map = {'1.2.3.4': 'my-host'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            percona_utils.HOSTS_FILE = tmpfile.name

            with open(tmpfile.name, 'w') as fd:
                fd.write("%s %s\n" % (map.items()[0]))

            percona_utils.update_hosts_file(map)

        with open(tmpfile.name, 'r') as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "%s %s\n" % (map.items()[0]))

    @mock.patch("percona_utils.log")
    def test_update_hosts_file_entry(self, mock_log):
        altmap = {'1.1.1.1': 'alt-host'}
        map = {'1.1.1.1': 'hostA',
               '2.2.2.2': 'hostB',
               '3.3.3.3': 'hostC',
               '4.4.4.4': 'hostD'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            percona_utils.HOSTS_FILE = tmpfile.name

            with open(tmpfile.name, 'w') as fd:
                fd.write("#somedata\n")
                fd.write("%s %s\n" % (altmap.items()[0]))

            percona_utils.update_hosts_file(map)

        with open(percona_utils.HOSTS_FILE, 'r') as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], "#somedata\n")
        self.assertEqual(lines[1], "%s %s\n" % (map.items()[0]))
        self.assertEqual(lines[4], "%s %s\n" % (map.items()[3]))

    @mock.patch("percona_utils.log")
    @mock.patch("percona_utils.config")
    @mock.patch("percona_utils.update_hosts_file")
    @mock.patch("percona_utils.get_host_ip")
    @mock.patch("percona_utils.relation_get")
    @mock.patch("percona_utils.related_units")
    @mock.patch("percona_utils.relation_ids")
    def test_get_cluster_hosts(self, mock_rel_ids, mock_rel_units,
                               mock_rel_get, mock_get_host_ip,
                               mock_update_hosts_file, mock_config,
                               mock_log):
        mock_rel_ids.return_value = [1]
        mock_rel_units.return_value = [2]
        mock_get_host_ip.return_value = 'hostA'

        def _mock_rel_get(key, *args):
            return {'private-address': '0.0.0.0'}

        mock_rel_get.side_effect = _mock_rel_get
        mock_config.side_effect = lambda k: False

        hosts = percona_utils.get_cluster_hosts()

        self.assertFalse(mock_update_hosts_file.called)
        mock_rel_get.assert_called_with(2, 1)
        self.assertEqual(hosts, ['hostA', 'hostA'])

    @mock.patch("percona_utils.log")
    @mock.patch("percona_utils.config")
    @mock.patch("percona_utils.update_hosts_file")
    @mock.patch("percona_utils.get_host_ip")
    @mock.patch("percona_utils.relation_get")
    @mock.patch("percona_utils.related_units")
    @mock.patch("percona_utils.relation_ids")
    def test_get_cluster_hosts_ipv6(self, mock_rel_ids, mock_rel_units,
                                    mock_rel_get, mock_get_host_ip,
                                    mock_update_hosts_file, mock_config,
                                    mock_log):
        mock_rel_ids.return_value = [1,2]
        mock_rel_units.return_value = [3,4]
        mock_get_host_ip.return_value = 'hostA'

        def _mock_rel_get(key, *args):
            return {'private-address': '0.0.0.0',
                    'hostname': 'hostB'}

        mock_rel_get.side_effect = _mock_rel_get
        mock_config.side_effect = lambda k: True

        hosts = percona_utils.get_cluster_hosts()

        mock_update_hosts_file.assert_called_with({'0.0.0.0': 'hostB'})
        mock_rel_get.assert_called_with(4, 2)
        self.assertEqual(hosts, ['hostA', 'hostB'])
