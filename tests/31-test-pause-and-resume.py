#!/usr/bin/python3
# test percona-cluster pause and resum

import basic_deployment
from charmhelpers.contrib.amulet.utils import AmuletUtils
# from charmhelpers.core.hookenv import status_get

def status_get(unit):
    import json
    raw_status = unit.run("status-get --format=json")
    status = json.loads(raw_status.decode("UTF-8"))
    return (status["status"], status["message"])

    # import subprocess
    # import json
    # cmd = ["juju", "run", "--unit", "percona-cluster/0",
    #        "'status-get'"]
    # raw_status = subprocess.check_output(cmd)
    # # status = json.loads(raw_status.decode("UTF-8"))
    # status = raw_status.decode("UTF-8")
    # return (status["status"], "")

utils = AmuletUtils()


class PauseResume(basic_deployment.BasicDeployment):

    def run(self):
        super(PauseResume, self).run()
        uid = 'percona-cluster/0'
        unit = self.d.sentry.unit[uid]
        assert self.is_mysqld_running(unit), 'mysql not running: %s' % uid
        assert status_get(unit)[0] == "unknown"
        
        action_id = utils.run_action(unit, "pause")
        assert utils.wait_on_action(action_id), "Pause action failed."


        # Note that is_mysqld_running will print an error message when
        # mysqld is not running.  This is by design but it looks odd
        # in the output.
        assert not self.is_mysqld_running(unit=unit), \
            "mysqld is still running!"
        init_contents = unit.directory_contents("/etc/init/")
        assert "mysql.override" in init_contents["files"], \
            "Override file not created."

        assert status_get(unit)[0] == "maintenance"
        action_id = utils.run_action(unit, "resume")
        assert utils.wait_on_action(action_id), "Resume action failed"
        assert status_get(unit)[0] == "active"
        init_contents = unit.directory_contents("/etc/init/")
        assert "mysql.override" not in init_contents["files"], \
            "Override file not removed."
        assert self.is_mysqld_running(unit=unit), \
            "mysqld not running after resume."


if __name__ == "__main__":
    p = PauseResume()
    p.run()
