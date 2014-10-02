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

    def test_update_empty_hosts_file(self):
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

    def test_update_hosts_file_w_dup(self):
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

    def test_update_hosts_file_entry(self):
        altmap = {'2.4.6.8': 'alt-host'}
        map = {'1.2.3.4': 'my-host'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            percona_utils.HOSTS_FILE = tmpfile.name

            with open(tmpfile.name, 'w') as fd:
                fd.write("%s %s\n" % (altmap.items()[0]))

            percona_utils.update_hosts_file(map)

        with open(tmpfile.name, 'r') as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "%s %s\n" % (altmap.items()[0]))
        self.assertEqual(lines[1], "%s %s\n" % (map.items()[0]))

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
        mock_rel_ids.return_value = [1,2]
        mock_rel_units.return_value = [3,4]
        mock_rel_get.return_value = '0.0.0.0'
        mock_config.side_effect = lambda k: False

        percona_utils.get_cluster_hosts()

        mock_rel_get.assert_called_with('private-address', 4, 2)

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
        mock_rel_get.return_value = '0.0.0.0'
        mock_config.side_effect = lambda k: True

        percona_utils.get_cluster_hosts()

        mock_rel_get.assert_called_with('hostname', 4, 2)
