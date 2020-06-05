import socket
import struct
import textwrap

tab_1 = '\t - '
tab_2 = '\t\t - '
tab_3 = '\t\t\t - '
tab_4 = '\t\t\t\t - '

data_tab_1 = '\t '
data_tab_2 = '\t\t '
data_tab_3 = '\t\t\t '
data_tab_4 = '\t\t\t\t '

def main():

    conn = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3))

    while True:
        raw_data , addr = conn.recvfrom(65536)
        dst_mac , src_mac , eth_proto , data = ethernet_frame(raw_data)
        print('\nEthernet Frame :')
        print(tab_1 + 'Destination : {} , Source : {} , Protocol : {}').format(dest_mac , src_mac , eth_proto)

        if eth_proto == 8:
            (version , header_lenght , ttl , proto , src , target , data) = ipv4_packet(data)
            print(tab_1 + 'IPv4 Packet :')
            print(tab_2 + 'Version : {} , header length : {} , ttl : {}'.format(version , header_lenght , ttl))
            print(tab_2 + 'Protocol : {} , Source : {} , Target : {}'.format(proto , src , target))

            # icmp
            if proto == 1:    
                icmp_type , code , checksum , data = icmp_packet(data)
                print(tab_1 + 'ICMP Packet :')
                print(tab_2 + 'type : {} , code : {} , checksum : {}'.format(icmp_type , code , checksum))
                print(tab_2 + 'DATA :')
                print(format_multi_line(data_tab_3 , data))

            #tcp
            elif proto == 6:
                (src_port , dst_port , sequence , acknowledgement , flag_urg , flag_ack , flag_psh , flag_rst , flag_syn , flag_fin) = tcp_segment(data)
                print(tab_1 + 'TCP Segment :')
                print(tab_2 + 'source port : {} , destination port : {}'.format(src_port , dst_port))
                print(tab_2 + 'sequence : {} , acknowledgement : {}'.format(sequence , acknowledgement))
                print(tab_2 + 'flags : ')
                print(tab_3 + 'urg : {} , ack : {} , psh : {} , rst : {} , syn : {} , fin : {}'.format(flag_urg , flag_ack , flag_psh , flag_rst , flag_syn , flag_fin))
                print(tab_2 + 'DATA :')
                print(format_multi_line(data_tab_3 , data))
            
            #udp
            elif proto == 17:
                src_port , dst_port , lenght , data = udp_segment(data)
                print(tab_1 + 'UDP Segment :')
                print(tab_2 + 'source port : {} , destination port : {} , length : {}'.format(src_port , dst_port , lenght))
            
            else:
                print(tab_1 + 'Data : ')
                print(format_multi_line(data_tab_2 , data))
        else:
            print(tab_1 + 'Data : ')
            print(format_multi_line(data_tab_2 , data))


def ethernet_frame(data):

    dest_mac , src_mac , proto = struct.unpack('! 6s 6s H' , data[:14])
    return get_mac_address(dest_mac) , get_mac_address(src_mac) , socket.htons(proto) , data[:14]


def get_mac_address(bytes_addr):

    bytes_str = map('{:02x}'.format , bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

def ipv4_packet(data):

    version_header_lenght = data[0]
    version = version_header_lenght >> 4
    header_lenght = (version_header_lenght & 15) * 4
    ttl , proto , src , target = struct.unpack('! 8x B B 2x 4s 4s' , data[:20])
    return version , header_lenght , ttl , proto , ipv4(src) , ipv4(target) , data[header_lenght:]

def ipv4(addr):

    return '.'.join(map(str , addr))

def icmp_packet(data):
    icmp_type , code , checksum = struct.unpack('! B B H' , data[:4])
    return icmp_type , code , checksum , data[4:]

def tcp_segment(data):

    (src_port , dst_port , sequence , acknowledgement , offset_reserved_flags) = struct.unpack('! H H L L H' , data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return src_port , dst_port , sequence , acknowledgement , flag_urg , flag_ack , flag_psh , flag_rst , flag_syn , flag_fin , data[offset:]

def udp_segment(data):

    src_port , dst_port , size = struct.unpack('! H H 2x H' , data[:8])
    return src_port , dst_port , size , data[8:]

def format_multi_line(prefix , string , size = 80):
    
    size -= len(prefix)
    if isinstance(string , bytes):
        string = '.'.join(r'\x[:02x]'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string , size)])



if __name__ == "__main__":

    main()