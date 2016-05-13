# nat-depth-measurer

######Measures divergence point of outgoing udp packets

  Advanced NAT traversal includes techniques such as analyzing the network, choosing web-based TCP relaying over TURN, setting the Time-To-Live of outgoing packets, analyzing incoming ICMP packets, setting firewall to block connection disrupters, etc.

  Sample code uses a UDP socket to read incoming ICMP packets (no root permission required) to measure the depth between a node and its router for hole punching purposes (to set the Time-To-Live on outbound hole punching packets):
https://github.com/JohnReedLOL/nat-depth-measurer/blob/master/main.cpp

  It basically says "you are 5 hops away from the point in which outgoing packets diverge, so the minimum TTL to set is 5. If the TTL is too high, the hole punching packet might travel too far and potentially triggering network security. If the TTL is too low, the peer might not be able to punch through.

  Currently the raw data that was used to write the paper is located at:
https://www.dropbox.com/sh/gjz92wfpg2njvbh/AAAfGSm7m07JnRDxdp9CgCRda?dl=0

  Ultimately I concluded that ICE or some variant of the Interactive Connectivity Establishment was the most convenient way to do peer-to-peer, but in cases where TCP relay was not an option, a "smarter" hole punching algorithm can be leveraged - one that gives more power to the end nodes.
