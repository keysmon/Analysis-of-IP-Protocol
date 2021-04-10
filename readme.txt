Hang Ruan V00923058

To run:
python3 p3.py file_name.pcap
(ie. python3 p3.py traceroute-frag.pcap)

1. The specification on the value in the protocol field of IP header was not clear. I understand that we should ignore dns but there're also SSDP packets which are udp packets. I'm not sure whether that count as one UDP in our output. In this case, i assume it doesn't count towards UDP as it's not relevant for exploring trace routes

2. In requirement 2 part 4, it was given that if the intermediate routers is not the same, then we don't have list the average RTT. But I still listed group1 trace files just in case.