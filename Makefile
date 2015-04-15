#!/usr/bin/make
PYTHON := /usr/bin/env python
export PYTHONPATH := hooks

lint:
	@flake8 --exclude hooks/charmhelpers hooks
	@charm proof

unit_test:
	@$(PYTHON) /usr/bin/nosetests --nologcapture unit_tests

test:
	@echo Starting amulet tests...
	#NOTE(beisner): can remove -v after bug 1320357 is fixed
	#   https://bugs.launchpad.net/amulet/+bug/1320357
	@juju test -v -p AMULET_HTTP_PROXY,AMULET_OS_VIP --timeout 900

bin/charm_helpers_sync.py:
	@mkdir -p bin
	@bzr cat lp:charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
        > bin/charm_helpers_sync.py

sync: bin/charm_helpers_sync.py
	@$(PYTHON) bin/charm_helpers_sync.py -c charm-helpers.yaml
	@$(PYTHON) bin/charm_helpers_sync.py -c charm-helpers-tests.yaml

publish: lint
	bzr push lp:charms/trusty/percona-cluster
