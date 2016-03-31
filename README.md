Overview
========

Percona XtraDB Cluster is a high availability and high scalability solution for
MySQL clustering. Percona XtraDB Cluster integrates Percona Server with the
Galera library of MySQL high availability solutions in a single product package
which enables you to create a cost-effective MySQL cluster.

This charm deploys Percona XtraDB Cluster onto Ubuntu.

Usage
=====

WARNING: Its critical that you follow the bootstrap process detailed in this
document in order to end up with a running Active/Active Percona Cluster.

Proxy Configuration
-------------------

If you are deploying this charm on MAAS or in an environment without direct
access to the internet, you will need to allow access to repo.percona.com
as the charm installs packages direct from the Percona respositories. If you
are using squid-deb-proxy, follow the steps below:

    echo "repo.percona.com" | sudo tee /etc/squid-deb-proxy/mirror-dstdomain.acl.d/40-percona
    sudo service squid-deb-proxy restart

Deployment
----------

The first service unit deployed acts as the seed node for the rest of the
cluster; in order for the cluster to function correctly, the same MySQL passwords
must be used across all nodes:

    cat > percona.yaml << EOF
    percona-cluster:
        root-password: my-root-password
        sst-password: my-sst-password
    EOF

Once you have created this file, you can deploy the first seed unit:

    juju deploy --config percona.yaml percona-cluster

Once this node is full operational, you can add extra units one at a time to the
deployment:

    juju add-unit percona-cluster

A minimium cluster size of three units is recommended.

In order to access the cluster, use the hacluster charm to provide a single IP
address:

    juju set percona-cluster vip=10.0.3.200
    juju deploy hacluster
    juju add-relation hacluster percona-cluster

Clients can then access using the vip provided.  This vip will be passed to
related services:

    juju add-relation keystone percona-cluster

Network Space support
---------------------

This charm supports the use of Juju Network Spaces, allowing the charm to be bound to network space configurations managed directly by Juju.  This is only supported with Juju 2.0 and above.

You can ensure that database connections are bound to a specific network space by binding the appropriate interfaces:

    juju deploy percona-cluster --bind "shared-db=internal-space"

alternatively these can also be provided as part of a juju native bundle configuration:

    percona-cluster:
      charm: cs:xenial/percona-cluster
      num_units: 1
      bindings:
        shared-db: internal-space

**NOTE:** Spaces must be configured in the underlying provider prior to attempting to use them.

**NOTE:** Existing deployments using the access-network configuration option will continue to function; this option is preferred over any network space binding provided if set.

Limitiations
============

Note that Percona XtraDB Cluster is not a 'scale-out' MySQL solution; reads
and writes are channelled through a single service unit and synchronously
replicated to other nodes in the cluster; reads/writes are as slow as the
slowest node you have in your deployment.
