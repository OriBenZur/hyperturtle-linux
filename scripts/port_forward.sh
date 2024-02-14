if [ $# -ne 3 ]; then
    echo "Usage: $0 <guest ip suffix> <host port> <guest port>"
    exit 1
fi

GUEST_SUFFIX=$1
HOST_PORT=$2
GUEST_PORT=$3
HOST_IP=$(ip -4 addr show eno2 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

sudo iptables -t nat -I PREROUTING -p tcp -d $HOST_IP --dport $HOST_PORT -j DNAT --to-destination 192.168.122.$GUEST_SUFFIX:$GUEST_PORT
sudo iptables -I FORWARD -m state -d 192.168.122.$GUEST_SUFFIX --state NEW,RELATED,ESTABLISHED -j ACCEPT
