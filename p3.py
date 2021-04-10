import struct
import sys

def windows_traceroute(fileContent):
    # record src_addr, dest_addr
    src_addr = 0
    dest_addr = 0
    addr_set = 0

    max_ttl = 0 # max ttl of echo packets
    id = []     # Identifications of first frag in each datagram
    
    echo_packets = [] # IP_datagram's first packets
    fragments = []
    seq_list = [] # IP_datagram's first packets' seq
    return_packets = [] # all icmp return packets

    routers = [] #intermediate routers in order

    counter = 1
    while len(fileContent) != 0:
        
        #Package frame
        ts_sec,ts_usec,incl_len,orig_len,fileContent = package_frame(fileContent)
        
        #Ethernet frame
        dest,src,proto,fileContent = ethernet_frame(fileContent)
        #skip frame if not ipv4
        if(proto != 2048):
            fileContent = fileContent[orig_len-14:]
            counter += 1
            continue
            
        #Ipv4 frame
        identification, mf_flags, offsets,total_length, version,header_length,ttl,proto,src,dest,fileContent = ipv4_unpack(fileContent)
        
        if identification in id:
            new_packet = icmp(counter,src,dest,icmp_type,code,checksum,ttl,ts_sec,ts_usec,seq,identification,identifier,offsets)
            fragments.append(new_packet)
       
        
        # Filter icmp packet
        if(proto == 1):
            icmp_type, code , checksum = icmp_unpack(fileContent)
            
            if identification not in id:
                id.append(identification)
            
            
            #ICMP echo message
            if(icmp_type == 8):
                identifier,seq = icmp_echo_unpack(fileContent)
                new_packet = icmp(counter,src,dest,icmp_type,code,checksum,ttl,ts_sec,ts_usec,seq,identification,identifier,offsets)
                echo_packets.append(new_packet)
                
                #set source_addr and dest_addr
                if (not addr_set):
                    src_addr = src
                    dest_addr = dest
                    addr_set = 1
                    
                #find max ttl of traceroute
                if (ttl != max_ttl):
                    max_ttl = max(max_ttl,ttl)
                    seq_list.append(seq)
                
                # record the first fragment id to find num_frag
                
                
                #ICMP time exceeded message
            if( icmp_type == 11):
                version_headerLength = fileContent[8]
                icmp_value = 1
                ip_header_length = (version_headerLength&15) * 4
                seq = struct.unpack('! H',fileContent[8+ip_header_length+6:8+ip_header_length+8])[0]
                new_packet = icmp(counter,src,dest,icmp_type,code,checksum,ttl,ts_sec,ts_usec,seq,identification,identifier,offsets)
                return_packets.append(new_packet)
                
                #ICMP reply or port unreachable message
            if( icmp_type == 0 or icmp_type == 3):
                identifier,seq = icmp_echo_unpack(fileContent)
                new_packet = icmp(counter,src,dest,icmp_type,code,checksum,ttl,ts_sec,ts_usec,seq,identification,identifier,offsets)
                return_packets.append(new_packet)
                
        #jump to the start of next segments
        fileContent = fileContent[orig_len-14-header_length:]
        counter+=1
    
    for seq in seq_list:
        for return_icmp in return_packets:
            if return_icmp.seq == seq:
                if return_icmp.src_addr not in routers and return_icmp.src_addr != dest_addr:
                    routers.append(return_icmp.src_addr)
                
    #outputs
    print("The IP address of the source node:",src_addr)
    print("The IP address of the ultimate destination node:",dest_addr)
    print("The IP addresses of the intermediate destination node:")
    for x in range(len(routers)):
        print("\trouter", x+1,":",routers[x])
    print("")
    print("The value in the protocol field of IP headers:")
    print("\t1: ICMP")
    print("")
    
    
    d = 1
    for echo in echo_packets:
        num_frags = 0   # num of fragments
        frag_offset = 0 # last fragment's offset
        for frag in fragments:
            if(echo.id == frag.id):
                num_frags += 1
                frag_offset = frag.offset
        if num_frags != 0:
            num_frags += 1
        print("The number of fragments created from the orginal datagram id ",echo.id," is: ",num_frags,sep= "")
        print("The offset of the last fragment is:",frag_offset)
        print("")
        d += 1
        
    routers.append(dest_addr)
    for addr in routers: # iterate each intermediate router
        rtt = []
        for return_icmp in return_packets:
            if(return_icmp.src_addr == addr): # find the packet sent from this router
                end_time = return_icmp.timestamp
                for echo in echo_packets:
                    if(return_icmp.seq == echo.seq): #find the echo packet that matches return packet
                        for frag in echo_packets:
                            if (echo.id == frag.id): # find all frags of this ip datagram
                                rtt.append(end_time - echo.timestamp)
        print("The avg RTT between",src_addr,"and",addr,"is:",round(avg(rtt)*1000,6),"ms,",end = "")
        print("the s.d. is: ",round(std(rtt)*1000,6),"ms")
        
        
   
    #for r2 part4 (find rtt)
    #for ttl in range(1,max_ttl+1): # iterate through each ttl
        #rtt = []
        #for echo in echo_packets:
            #if echo.ttl == ttl: # echo packet with ttl
                #for return_pack in return_packets:
                    #if return_pack.seq == echo.seq:
                        #end_time = return_pack.timestamp # find the timestamp of the return packet
                        #break
                #for frag in echo_packets:
                    #if echo.id == frag.id:
                        #rtt.append(end_time - frag.timestamp)
        #print(round(avg(rtt)*1000,6))
    
    return
    
    
    
def linux_traceroute(fileContent):
    # record src_addr, dest_addr
    src_addr = 0
    dest_addr = 0
    addr_set = 0
    
    max_ttl = 0 # max ttl of udp packets
  
    id_list = [] # id's of all udp packets
    routers = [] # addr of all intermediate routers
    
    undefrag_packets = [] # IP_datagram's first packets' ports
    fragments = []  #IP datagram's non_first packet
    icmp_packets = [] #all icmp packets
    
    port_lists = [] # IP_datagram's first packets' ports
    
    counter = 1
    while len(fileContent) !=0:
        #Package frame
        ts_sec,ts_usec,incl_len,orig_len,fileContent = package_frame(fileContent)
        
        #Ethernet frame
        dest,src,proto,fileContent = ethernet_frame(fileContent)
        
        #skip frame if not ipv4
        if(proto != 2048):
            fileContent = fileContent[orig_len-14:]
            counter += 1
            continue
            
        #Ipv4 frame
        identification, mf_flags, offsets,total_length, version,header_length,ttl,proto,src,dest,fileContent = ipv4_unpack(fileContent)

        
        
        
        # protocol 17 -> udp packet
        if (proto == 17):
            src_port,dest_port,length,check_sum = udp_unpack(fileContent)
            
            #non-first fragments of each datagram
            if(identification in id_list):
                new_packet = udp_packet(src,dest,src_port,dest_port,proto,ttl,ts_sec,ts_usec,counter,identification,offsets)
                fragments.append(new_packet)
            #exclude irrelavent packets
            if(dest_port >= 33434 and dest_port<= 33529):
                id_list.append(identification)
            # set src_addr, dest_addr
                if (not addr_set):
                    src_addr = src
                    dest_addr = dest
                    addr_set = 1
           
        
            # store the packet
                new_packet = udp_packet(src,dest,src_port,dest_port,proto,ttl,ts_sec,ts_usec,counter,identification,offsets)
                #first fragment of each datagram
                undefrag_packets.append(new_packet)
                
                #if (max_ttl != ttl):
                # store the ports of first frags
                ports = [src_port,dest_port]
                port_lists.append(ports)
                
                # to find the max_ttl of udp
                max_ttl = max(max_ttl,ttl)
                
        #if icmp packet
        if(proto == 1):
            icmp_type, code , checksum = icmp_unpack(fileContent)
            if(icmp_type == 11 or icmp_type == 3):
                version_headerLength = fileContent[8]
                icmp_value = 1  # test whether icmp protocol in ipv4
                ip_header_length = (version_headerLength&15) * 4
                src_port, dest_port = struct.unpack('! H H',fileContent[8+ip_header_length:8+ip_header_length+4])
        
                new_packet = icmp_packet(counter,src,dest,src_port,dest_port,icmp_type,code,checksum,ttl,ts_sec,ts_usec)
                icmp_packets.append(new_packet)
            
        #jump to the start of next segments
        fileContent = fileContent[orig_len-14-header_length:]
        counter+=1
        
    #find intermediate routers based on ports
    for ports in port_lists:
        for icmp in icmp_packets:
            if (ports[0] == icmp.source_port and ports[1] == icmp.dest_port):
                if(icmp.src_addr != dest_addr):
                    if(icmp.src_addr not in routers):
                        routers.append(icmp.src_addr)
    #outputs
    print("The IP address of the source node:",src_addr)
    print("The IP address of the ultimate destination node:",dest_addr)
    
    print("The IP addresses of the intermediate destination node:")
    for x in range(len(routers)):
        print("\trouter", x+1,":",routers[x])
    print("")
    print("The value in the protocol field of IP headers:")
    print("\t1: ICMP")
    print("\t17: UDP\n")
    
    
    for udp in undefrag_packets:
        num_frags = 0   # num of fragments
        frag_offset = 0 # last fragment's offset
        for frag in fragments:
            if(udp.id == frag.id):
                num_frags += 1
                frag_offset = frag.offset
        if num_frags != 0:
            num_frags += 1
        print("The number of fragments created from the orginal datagram id ",udp.id," is: ",num_frags,sep= "")
        print("The offset of the last fragment is:",frag_offset)
        print("")
        
    
    
    
    routers.append(dest_addr)
    for addr in routers: # iterate each router
        rtt = []
        for icmp in icmp_packets: # find icmps with matching sourceaddress
            end_time = icmp.timestamp
            if(icmp.src_addr == addr):
                for udp in undefrag_packets: # find the original udp
                    if(udp.src_port == icmp.source_port):
                        rtt.append(end_time - udp.timestamp )
                        for frag in fragments: # find the fragments with the same ID
                            if (frag.id == udp.id):
                                rtt.append(end_time - frag.timestamp)
        print("The avg RTT between",src_addr,"and",addr,"is:",round(avg(rtt)*1000,6),"ms,",end = "")
        print("the s.d. is: ",round(std(rtt)*1000,6),"ms")
        
    #for r2 part4 (find rtt)
    #for ttl in range(1,max_ttl+1): #iterate ttl
        #rtt = []
        #for udp in undefrag_packets:
            #if (udp.ttl == ttl): # find a packet with this ttl
                #for icmp in icmp_packets:
                    #if(udp.src_port == icmp.source_port): # match the return icmp packet
                        #end_time = icmp.timestamp
                        #break
                #rtt.append(end_time - udp.timestamp)
                #for frag in fragments:
                    #if (udp.id == frag.id):
                        #rtt.append(end_time - frag.timestamp)
                    
        #print(round(avg(rtt)*1000,6))
    return


class icmp():
    
    id = 0
    no = 0
    src_addr = 0
    dest_addr = 0
    type = 0
    code = 0
    checksum = 0
    ttl = 0
    timestamp = 0
    seq = 0
    identifier = 0
    offset = 0
    
    def __init__ (self,no,src_addr,dest_addr,type,code,checksum,time_to_live,sec,usec,seq,id,identifier,offset):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.type = 0
        self.code = 0
        self.checksum = 0
        self.ttl = time_to_live
        self.timestamp = sec + usec * 0.000000001
        self.no = no
        self.seq = seq
        self.id = id
        self.identifier = identifier
        self.offset = offset

class udp_packet():
    id = 0
    no = 0
    src_addr = 0
    dest_addr = 0
    src_port = 0
    dest_port = 0
    proto = 0
    ttl = 0
    timestamp = 0
    offset = 0
    def __init__ (self,src_addr,dest_addr,src_port,dest_port,proto,time_to_live,sec,usec,no,id,offset):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.proto = proto
        self.ttl = time_to_live
        self.timestamp = sec + usec * 0.000000001
        self.no = no
        self.id = id
        self.offset = offset
        
class icmp_packet():
    no = 0
    src_addr = 0
    dest_addr = 0
    source_port = 0
    dest_port = 0
    type = 0
    code = 0
    checksum = 0
    ttl = 0
    timestamp = 0
    def __init__ (self,no,src_addr,dest_addr,src_port,dest_port,type,code,checksum,time_to_live,sec,usec):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.source_port = src_port
        self.dest_port = dest_port
        self.type = 0
        self.code = 0
        self.checksum = 0
        self.ttl = time_to_live
        self.timestamp = sec + usec * 0.000000001
        self.no = no

def package_frame(data):
    ts_sec,ts_usec,incl_len,orig_len = struct.unpack('I I I I',data[:16])
    return ts_sec,ts_usec,incl_len,orig_len,data[16:]

#get dest_address,src_address and protocol
def ethernet_frame(data):
    dest,src,proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_address(dest),get_mac_address(src),proto,data[14:]
    
#format address into the format AA:BB:CC:DD:EE:FF
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#unpack ip_header info
def ipv4_unpack(data):
    version_headerLength = data[0]
    version = version_headerLength >> 4
    header_length = (version_headerLength&15) * 4
    id = struct.unpack('!H',data[4:6])[0]
    flags_offsets = struct.unpack('! H',data[6:8])[0]
    mf_flags = (flags_offsets << 2) >> 15
    temp_offsets = (flags_offsets &0x1FFF)
    top = temp_offsets >> 8
    bottom = temp_offsets & 0xFF
    offsets = top + bottom * 8
    total_length = struct.unpack('! H',data[2:4])[0]
    ttl,proto,src,dest = struct.unpack('!8x B B 2x 4s 4s',data[:20])
    return id,mf_flags, offsets, total_length,version,header_length,ttl,proto,ipv4(src),ipv4(dest),data[header_length:]
    
#format ip_address
def ipv4(addr):
    return '.'.join(map(str,addr))

def icmp_unpack(data):
    icmp_type,code,checksum = struct.unpack( '! B B H',data[:4])
    return icmp_type, code , checksum

def icmp_echo_unpack(data):
    identification,seq = struct.unpack( '!H H',data[4:8])
    return identification,seq
    
def udp_unpack(data):
    src_port,dest_port,length,check_sum = struct.unpack( '! H H H H',data[:8])
    return src_port,dest_port,length,check_sum

def avg(list):
    return sum(list)/len(list)

def std(list):
    var = sum([((x - avg(list))**2) for x in list])/len(list)
    return var ** 0.5



def main(argv):
    #readfile
    file_name = argv[1]
    try:
        f = open(file_name,"rb")
    except IOError:
        print ("Error! File not exist")
        return
    fileContent = f.read()
    fileContent = fileContent[24:]
    temp = fileContent
    
    #find the system's environment(linux or win)
    while len(temp) != 0:
        
        orig_len = struct.unpack('I',temp[12:16])[0]
        temp =temp[16:]
        dest,src,proto,temp = ethernet_frame(temp)
        #if not ipv4
        if(proto != 2048):
            temp = temp[orig_len-14:]
            continue
    
        identification,mf_flags, offsets,total_length, version,header_length,ttl,proto,src,dest,temp = ipv4_unpack(temp)
        
        if (proto ==17):
            src_port,dest_port,length,check_sum = udp_unpack(temp)
           
            if(dest_port >= 33434 and dest_port<= 33529):
                linux_traceroute(fileContent)
                break
                
        if(proto == 1):
            icmp_type, code , checksum = icmp_unpack(temp)
            if(icmp_type == 8):
                windows_traceroute(fileContent)
                break
        temp = temp[orig_len-14-header_length:]
    f.close()
    
    
    
    
    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Invalid argrument! Exiting")
    else:
        main(sys.argv)
