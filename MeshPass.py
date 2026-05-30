# MeshPass

import socket
import struct
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# Define the UDP IP address and port to listen on
MULTICAST_UDP_IP = '224.0.0.86'
MULTICAST_UDP_PORT = 5005
MULTICAST_TUPLE = (MULTICAST_UDP_IP, MULTICAST_UDP_PORT)
MULTICAST_TTL = 1


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
MY_IP_ADDRESS = s.getsockname()[0]
s.close()
HEADER_LEN = 64
#SERVER_TCP_PORT = 5050
FORMAT = 'utf-8'
MYHOSTNAME = socket.gethostname()
#MY_IP_ADDRESS = socket.gethostbyname(MYHOSTNAME)
#MY_OTHER_IP_ADDRESS = socket.gethostbyaddr(MYHOSTNAME)
MY_TCP_PORT = 5051

MY_SOCKET_TUPLE = (MY_IP_ADDRESS, MY_TCP_PORT)
CLIENT_SOCKET_TUPLE = ()
DISCONNECT_MESSAGE = "!DISCONNECT"
KEY_EXCHANGE_MESSAGE = '!KEY_EXCHANGE'
PARAMETER_REQUEST_MESSAGE = '!PARAMETER_REQUEST'
KEY_MATERIAL_READY = '!KEY_MATERIAL_READY'
PARAMETERS_RESPONSE = '!PARAMETERS_RESPONSE'


def main(cli_args):
    print(f'Listening for UDP packets on {MULTICAST_UDP_IP}:{MULTICAST_UDP_PORT}')
    print(f"my host name: {MYHOSTNAME}")
    print(f"my ip address: {MY_IP_ADDRESS}")

    # Create a UDP socket
    multicast_listen_udp_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    multicast_listen_udp_socket_obj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) #This line has something to do with timeouts and avoiding errors due to timeouts.
    #multicast_listen_udp_socket_obj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) #This line has something to do with timeouts and avoiding errors due to timeouts.
    
    multicast_listen_udp_socket_obj.bind(MULTICAST_TUPLE)
    
    mreq = struct.pack('4sl', socket.inet_aton(MULTICAST_UDP_IP), socket.INADDR_ANY)
    multicast_listen_udp_socket_obj.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


    #multicast_listen_udp_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #multicast_listen_udp_socket_obj.bind(MULTICAST_TUPLE)
    multicast_send_udp_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    multicast_send_udp_socket_obj.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)

    #set up TCP server socket to listen for sync requests
    my_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create TCP socket
    my_socket_obj.bind(MY_SOCKET_TUPLE)              # bind socket to address and port

    #server_socket_obj.listen()
    #multicast_listen_udp_socket_obj_list = [multicast_listen_udp_socket_obj]
    #multicast_listen_udp_socket_obj_tup = tuple({multicast_listen_udp_socket_obj})
    thread_udp = threading.Thread(target=listen_for_multicasts,
                              args=(multicast_listen_udp_socket_obj,)
                             )
    thread_udp.start()
    #my_socket_obj_list = [my_socket_obj]
    #my_socket_obj_tup = tuple((my_socket_obj))
    thread_tcp = threading.Thread(target=listen_for_tcp,
                              args=(my_socket_obj,)
                             )
    thread_tcp.start()

    print(f'MeshPass> ', end='')
    while True:
        command = input().upper()
        if command == 'FIND':
            send_multicast(multicast_send_udp_socket_obj)
        elif command == 'EXIT':
            multicast_listen_udp_socket_obj.close()
            multicast_send_udp_socket_obj.close()
            my_socket_obj.close()
            exit()

def listen_for_multicasts(multicast_listen_udp_socket_obj):
    while True:
        # Receive data from the socket
        data, partner_socket_tuple = multicast_listen_udp_socket_obj.recvfrom(1024)
        message = data.decode('utf-8')
        if message == MY_IP_ADDRESS:
            print(f'{partner_socket_tuple}: This is me.')
            return
        print(f'Received packet from {partner_socket_tuple}: {message}')    
        print(f'{MY_IP_ADDRESS}')
        #respond by setting up TCP connection.
        my_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket_obj.connect(partner_socket_tuple)

def send_multicast(multicast_send_udp_socket_obj):
    message = f'{MY_IP_ADDRESS}'
    try:
        print(f'{MULTICAST_UDP_IP}, {MULTICAST_UDP_PORT}, {message}')
        multicast_send_udp_socket_obj.sendto(message.encode(),
                             (MULTICAST_UDP_IP, MULTICAST_UDP_PORT)
                            )
        print(f'Sent UDP packet to {MULTICAST_UDP_IP}:'
              f'{MULTICAST_UDP_PORT}: {message}')
    #print(f"[LISTENING] Server is listening on {MY_IP_ADDRESS}")
    except:
        print(f'exception')

def listen_for_tcp(my_socket_obj):
    my_socket_obj.listen()
    while True:
        partner_socket_obj, partner_ip_address = my_socket_obj.accept()
        print(f"type of conn: {type(partner_socket_obj)}")
        thread = threading.Thread(target=handle_incoming_call,
                                  args=(partner_socket_obj, partner_ip_address))
        print(f"type of thread: {type(thread)}")
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count()-1}")



print("[STARTING] server is starting...")


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))