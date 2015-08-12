#!/usr/bin/python3
# test percona-cluster pause and resume

import subprocess
import sys
import time

import json

import basic_deployment


class PauseResume(basic_deployment.BasicDeployment):

    def _run_action(self, unit_id, action, *args):
        command = ["juju", "action", "do", "--format=json", unit_id, action]
        command.extend(args)
        print("Running command: %s\n" % " ".join(command))
        output = subprocess.check_output(command)
        output_json = output.decode(encoding="UTF-8")
        data = json.loads(output_json)
        action_id = data[u'Action queued with id']
        return action_id

    def _wait_on_action(self, action_id):
        command = ["juju", "action", "fetch", "--format=json", action_id]
        while True:
            try:
                output = subprocess.check_output(command)
            except Exception as e:
                print(e)
                return False
            output_json = output.decode(encoding="UTF-8")
            data = json.loads(output_json)
            if data[u"status"] == "completed":
                return True
            elif data[u"status"] == "failed":
                return False
            time.sleep(2)

    def run(self):
        super(PauseResume, self).run()
        unit_name = "percona-cluster/0"
        unit = self.d.sentry.unit[unit_name]
        assert self.is_mysqld_running(unit=unit), "mysqld not running in initial state."
        action_id = self._run_action(unit_name, "pause")
        assert self._wait_on_action(action_id), "Pause action failed."

        # Note that is_mysqld_running will print an error message when
        # mysqld is not running.  This is by design but it looks odd
        # in the output.
        assert not self.is_mysqld_running(unit=unit), "mysqld is still running!"
        init_contents = unit.directory_contents("/etc/init/")
        assert "mysql.override" in init_contents["files"], "Override file not created."

        action_id = self._run_action(unit_name, "resume")
        assert self._wait_on_action(action_id), "Resume action failed"
        init_contents = unit.directory_contents("/etc/init/")
        assert "mysql.override" not in init_contents["files"], "Override file not removed."
        assert self.is_mysqld_running(unit=unit), "mysqld not running after resume."


if __name__ == "__main__":
    p = PauseResume()
    p.run()
