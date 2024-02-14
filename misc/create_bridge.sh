brctl addbr br0
sudo ifconfig br0 132.68.52.130  netmask 255.255.255.128  broadcast 132.68.52.255
brctl addif br0 eth2