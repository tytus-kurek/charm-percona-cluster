#!/bin/bash -ex
# The script installs amulet and other tools needed for the amulet tests.

# Get the status of the amulet package, this returns 0 of package is installed.
dpkg -s amulet
if [ $? -ne 0 ]; then
  # Install the Amulet testing harness.
  sudo add-apt-repository -y ppa:juju/stable
  sudo apt-get update 
  sudo apt-get install -y amulet juju-core charm-tools
fi


PACKAGES="python3 python3-yaml"
for pkg in $PACKAGES; do
  dpkg -s python3
  if [ $? -ne 0 ]; then
    sudo apt-get install -y -q $pkg
  fi
done
