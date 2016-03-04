#!/usr/bin/python

import os
import sys
import subprocess
import traceback
from time import gmtime, strftime

from charmhelpers.core.host import service_pause, service_resume
from charmhelpers.core.hookenv import (
    action_get,
    action_set,
    action_fail,
    status_set,
    config,
)

from percona_utils import assess_status

MYSQL_SERVICE = "mysql"


def pause(args):
    """Pause the MySQL service.

    @raises Exception should the service fail to stop.
    """
    if not service_pause(MYSQL_SERVICE):
        raise Exception("Failed to pause MySQL service.")
    status_set(
        "maintenance",
        "Unit paused - use 'resume' action to resume normal service")


def resume(args):
    """Resume the MySQL service.

    @raises Exception should the service fail to start."""
    if not service_resume(MYSQL_SERVICE):
        raise Exception("Failed to resume MySQL service.")
    assess_status()


def backup():
    basedir = (action_get("basedir")).lower()
    compress = (action_get("compress"))
    incremental = (action_get("incremental"))
    sstpw = config("sst-password")
    optionlist = []

    # innobackupex will not create recursive dirs that do not already exist,
    # so help it along
    if not os.path.exists(basedir):
        os.makedirs(basedir)

    # Build a list of options to pass to innobackupex
    if compress is "true":
        optionlist.append("--compress")

    if incremental is "true":
        optionlist.append("--incremental")

    try:
        subprocess.check_call(
            ['innobackupex', '--compact', '--galera-info', '--rsync',
             basedir, '--user=sstuser', '--password=' + sstpw] + optionlist)
        action_set({
            'time-completed': (strftime("%Y-%m-%d %H:%M:%S", gmtime())),
            'outcome': 'Success'}
        )
    except subprocess.CalledProcessError as e:
        action_set({
            'time-completed': (strftime("%Y-%m-%d %H:%M:%S", gmtime())),
            'output': e.output,
            'return-code': e.returncode,
            'traceback': traceback.format_exc()})
        action_fail("innobackupex failed, you should log on to the unit"
                    "and check the status of the database")

# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume, "backup": backup}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action %s undefined" % action_name
    else:
        try:
            action(args)
        except Exception as e:
            action_fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
