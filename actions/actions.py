#!/usr/bin/python

import os
import sys

from charmhelpers.core.host import service_pause, service_resume
from charmhelpers.core.hookenv import action_fail, status_set
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


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume}


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
