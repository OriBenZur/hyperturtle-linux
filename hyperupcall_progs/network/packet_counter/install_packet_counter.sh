executable_path=$(dirname "$0")
(sudo $executable_path/packet_counter.guest) &
echo $!
