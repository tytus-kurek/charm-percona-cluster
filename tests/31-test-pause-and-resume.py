#!/usr/bin/python3
# test percona-cluster pause and resume

import subprocess
import sys
import time

import json

import basic_deployment
from charmhelpers.contrib.amulet.utils import AmuletUtils

utils = AmuletUtils()

class PauseResume(basic_deployment.BasicDeployment):

    def run(self):
        super(PauseResume, self).run()
        unit_name = "percona-cluster/0"
        unit = self.d.sentry.unit[unit_name]
        assert self.is_mysqld_running(unit=unit), "mysqld not running in initial state."
        action_id = utils.run_action(self.d.sentry, "pause")
        assert utils.wait_on_action(action_id), "Pause action failed."

        # Note that is_mysqld_running will print an error message when
        # mysqld is not running.  This is by design but it looks odd
        # in the output.
        assert not self.is_mysqld_running(unit=unit), "mysqld is still running!"
        init_contents = unit.directory_contents("/etc/init/")
        assert "mysql.override" in init_contents["files"], "Override file not created."

        action_id = utils.run_action(self.d.sentry, "resume")
        assert utils.wait_on_action(action_id), "Resume action failed"
        init_contents = unit.directory_contents("/etc/init/")
        assert "mysql.override" not in init_contents["files"], "Override file not removed."
        assert self.is_mysqld_running(unit=unit), "mysqld not running after resume."


if __name__ == "__main__":
    p = PauseResume()
    p.run()
