Overview
========

Percona XtraDB Cluster is a high availability and high scalability solution for
MySQL clustering. Percona XtraDB Cluster integrates Percona Server with the
Galera library of MySQL high availability solutions in a single product package
which enables you to create a cost-effective MySQL cluster.

This charm deploys Percona XtraDB Cluster onto Ubuntu.

Usage
=====

Deployment
----------

To deploy this charm:

    juju deploy percona-cluster

Passwords required for the correct operation of the deployment are automatically
generated and stored by the lead unit (typically the first unit).

To expand the deployment:

    juju add-unit -n 2 percona-cluster

See notes in the 'HA/Clustering' section on safely deploying a PXC cluster
in a single action.

The root password for mysql can be retrieved using the following command:

    juju run --unit percona-cluster/0 leader-get root-password

This is only usable from within one of the units within the deployment
(access to root is restricted to localhost only).

Memory Configuration
-------------------

Percona Cluster is extremely memory sensitive. Setting memory values too low
will give poor performance. Setting them too high will create problems that are
very difficult to diagnose. Please take time to evaluate these settings for
each deployment environment rather than copying and pasting bundle
configurations.

The Percona Cluster charm needs to be able to be deployed in small low memory
development environments as well as high performance production environments.
The charm configuration opinionated defaults favor the developer environment in
order to ease initial testing. Production environments need to consider
carefully the memory requirements for the hardware or cloud in use. Consult a
MySQL memory calculator [2] to understand the implications of the values.

Between the 5.5 and 5.6 releases a significant default was changed.
The performance schema [1] defaulted to on for 5.6 and later. This allocates
all the memory that would be required to handle max-connections plus several
other memory settings. With 5.5 memory was allocated during runtime as needed.

The charm now makes performance schema configurable and defaults to off (False).
With the performance schema turned off memory is allocated when needed during
run time. It is important to understand this can lead to run time memory
exhaustion if the configuration values are set too high. Consult a MySQL memory
calculator [2] to understand the implications of the values.

Particularly consider the max-connections setting, this value is a balance
between connection exhaustion and memory exhaustion. Occasionally connection
exhaustion occurs in large production HA clouds with max-connections less than
2000. The common practice became to set max-connections unrealistically high
near 10k or 20k. In the move to 5.6 on Xenial this became a problem as Percona
would fail to start up or behave erratically as memory exhaustion occurred on
the host due to performance schema being turned on. Even with the default now
turned off this value should be carefully considered against the production
requirements and resources available.

[1] http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-6.html#mysqld-5-6-6-performance-schema
[2] http://www.mysqlcalculator.com/


HA/Clustering
-------------

When more than one unit of the charm is deployed with the hacluster charm
the percona charm will bring up an Active/Active cluster. The process of
clustering the units together takes some time. Due to the nature of
asynchronous hook execution it is possible client relationship hooks may
be executed before the cluster is complete. In some cases, this can lead
to client charm errors.

To guarantee client relation hooks will not be executed until clustering is
completed use the min-cluster-size configuration setting:

    juju deploy -n 3 percona-cluster
    juju config percona-cluster min-cluster-size=3

When min-cluster-size is not set the charm will still cluster, however,
there are no guarantees client relation hooks will not execute before it is
complete.

Single unit deployments behave as expected.

There are two mutually exclusive high availability options: using virtual
IP(s) or DNS. In both cases, a relationship to hacluster is required which
provides the corosync back end HA functionality.

To use virtual IP(s) the clustered nodes must be on the same subnet such that
the VIP is a valid IP on the subnet for one of the node's interfaces and each
node has an interface in said subnet. The VIP becomes a highly-available API
endpoint.

At a minimum, the config option 'vip' must be set in order to use virtual IP
HA. If multiple networks are being used, a VIP should be provided for each
network, separated by spaces. Optionally, vip_iface or vip_cidr may be
specified.

To use DNS high availability there are several prerequisites. However, DNS HA
does not require the clustered nodes to be on the same subnet.
Currently the DNS HA feature is only available for MAAS 2.0 or greater
environments. MAAS 2.0 requires Juju 2.0 or greater. The clustered nodes must
have static or "reserved" IP addresses registered in MAAS. The DNS hostname(s)
must be pre-registered in MAAS before use with DNS HA.

At a minimum, the config option 'dns-ha' must be set to true and
'os-access-hostname' must be set in order to use DNS HA.
The charm will throw an exception in the following circumstances:
If neither 'vip' nor 'dns-ha' is set and the charm is related to hacluster
If both 'vip' and 'dns-ha' are set as they are mutually exclusive
If 'dns-ha' is set and os-access-hostname is not set

Network Space support
---------------------

This charm supports the use of Juju Network Spaces, allowing the charm to be bound
to network space configurations managed directly by Juju.  This is only supported
with Juju 2.0 and above.

You can ensure that database connections and cluster peer communication are bound to
specific network spaces by binding the appropriate interfaces:

    juju deploy percona-cluster --bind "shared-db=internal-space,cluster=internal-space"

alternatively these can also be provided as part of a juju native bundle configuration:

    percona-cluster:
      charm: cs:xenial/percona-cluster
      num_units: 1
      bindings:
        shared-db: internal-space
        cluster: internal-space

The 'cluster' endpoint binding is used to determine which network space units within the
percona-cluster deployment should use for communication with each other; the 'shared-db'
endpoint binding is used to determine which network space should be used for access to
MySQL databases services from other charms.

**NOTE:** Spaces must be configured in the underlying provider prior to attempting to use them.

**NOTE:** Existing deployments using the access-network configuration option will continue to function; this option is preferred over any network space binding provided for the 'shared-db' relation if set.

Limitiations
============

Note that Percona XtraDB Cluster is not a 'scale-out' MySQL solution; reads
and writes are channelled through a single service unit and synchronously
replicated to other nodes in the cluster; reads/writes are as slow as the
slowest node you have in your deployment.
