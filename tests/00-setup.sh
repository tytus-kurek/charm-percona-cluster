#!/bin/bash -x
# The script installs amulet and other tools needed for the amulet tests.

# Get the status of the amulet package, this returns 0 of package is installed.
dpkg -s amulet
if [ $? -ne 0 ]; then
    # Install the Amulet testing harness.
  sudo add-apt-repository -y ppa:juju/stable
  sudo apt-get update 
  sudo apt-get install -y -q amulet juju-core charm-tools
fi

PACKAGES="python3 python3-yaml python-cinderclient python-distro-info python-glanceclient python-heatclient python-keystoneclient python-neutronclient python-novaclient python-pika python-swiftclient"
for pkg in $PACKAGES; do
  dpkg -s $pkg
  if [ $? -ne 0 ]; then
    sudo apt-get install -y -q $pkg
  fi
done


#if [ ! -f "$(dirname $0)/../local.yaml" ]; then
#  echo "To run these amulet tests a vip is needed, create a file called \
#local.yaml in the charm dir, this file must contain a 'vip', if you're \
#using the local provider with lxc you could use a free IP from the range \
#10.0.3.0/24"
#  exit 1
#fi
