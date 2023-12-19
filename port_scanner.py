""" This program was written by Yonatan Deri """
from scapy.all import *
from scapy.layers.inet import TCP, IP
import ipaddress


def scanning_functionality():
    """ The function is responsible for the scanning functionality (three way handshake). """
    is_valid_ip = False
    dst_ip = '127.0.0.1'  # overcoming the problem of "Local variable 'dst_ip' might be referenced before assignment".
    while not is_valid_ip:
        dst_ip = input("Please enter IP address to scan: ")
        try:
            ipaddress.ip_address(dst_ip)
            is_valid_ip = True
        except ValueError:
            print("Invalid IP address")

    print("Please enter the port range you would like to scan in your target")  # another way to do this is to enter
    # the string "beginning-end" and than split it in the '-' character.
    is_valid_begin_port = False
    begin_port = 80  # overcoming the problem of "Local variable 'begin_port' might be referenced before assignment".
    while not is_valid_begin_port:
        begin_port = input("beginning port: ")
        try:
            begin_port.isdigit()
            if not (1 <= int(begin_port) <= 65535):
                print("please enter a beginning port number in range of 1-65535")
            else:
                is_valid_begin_port = True
        except ValueError:
            print("please enter a beginning port number in range of 1-65535")

    is_valid_end_port = False
    end_port = 80  # overcoming the problem of "Local variable 'end_port' might be referenced before assignment".
    while not is_valid_end_port:
        end_port = input("end port: ")
        try:
            end_port.isdigit()
            if not (1 <= int(end_port) <= 65535):
                print("please enter an ending port number in range of 1-65535")
            else:
                is_valid_end_port = True
        except ValueError:
            print("please enter an ending port number in range of 1-65535")

    if int(end_port) >= (int(begin_port) + 1):
        for _ in range(int(begin_port), int(end_port) + 1):
            syn_segment = TCP(dport=_, seq=123, flags='S')  # the timeout is for the possibility that the server would
            # not send a response with a RST flag (on) saying that the port is closed. In addition the seq=123 is for
            # convention at this matter, because we work only with the flags of the TCP layer and not the data because
            # there is no data at this point to deal with.
            syn_packet = IP(dst=dst_ip)/syn_segment
            syn_ack_packet = sr1(syn_packet, timeout=10, verbose=0)
            if syn_ack_packet is not None:
                if syn_ack_packet.haslayer(TCP):
                    if syn_ack_packet[TCP].flags == "SA":  # "SA" = SYN-ACK flag.
                        send_reset_segment = TCP(dport=_, flags="AR")
                        send(IP(dst=dst_ip)/send_reset_segment, verbose=0)
                        print("\nport " + str(_) + " is open")
                    elif syn_ack_packet[TCP].flags == "R":  # "R" = RST flag.
                        print("\nport " + str(_) + " is closed or the server is not ready to pick up the link")
                else:
                    print("\nreceived a packet that doesn't have a TCP layer")
            else:
                print("\nport " + str(_) + " is closed")
    else:
        print("begin port number must be smaller than end port number")


if __name__ == '__main__':
    """ The function calls the other function, scanning_functionality(). """
    scanning_functionality()
