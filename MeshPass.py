# MeshPass

import socket
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# Define the UDP IP address and port to listen on
MULTICAST_UDP_IP = '224.0.0.71'
MULTICAST_UDP_PORT = 5005

print(f'Listening for UDP packets on {MULTICAST_UDP_IP}:{MULTICAST_UDP_PORT}')



HEADER_LEN = 64
#SERVER_TCP_PORT = 5050
FORMAT = 'utf-8'
MYHOSTNAME = socket.gethostname()
MY_IP_ADDRESS = socket.gethostbyname(MYHOSTNAME)
MY_TCP_PORT = 5050
print(f"my host name: {MYHOSTNAME}")
print(f"server ip address: {MY_IP_ADDRESS}")
MY_SOCKET_TUPLE = (MY_IP_ADDRESS, MY_TCP_PORT)
CLIENT_SOCKET_TUPLE = ()
DISCONNECT_MESSAGE = "!DISCONNECT"
KEY_EXCHANGE_MESSAGE = '!KEY_EXCHANGE'
PARAMETER_REQUEST_MESSAGE = '!PARAMETER_REQUEST'
KEY_MATERIAL_READY = '!KEY_MATERIAL_READY'
PARAMETERS_RESPONSE = '!PARAMETERS_RESPONSE'


def main(cli_args):

    # Create a UDP socket
    multicast_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    multicast_udp_sock.bind((MULTICAST_UDP_IP, MULTICAST_UDP_PORT))
    my_udp_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #set up TCP server socket to listen for sync requests
    my_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create TCP socket
    my_socket_obj.bind(MY_SOCKET_TUPLE)              # bind socket to address and port

    #server_socket_obj.listen()
    #multicast_udp_sock_list = [multicast_udp_sock]
    #multicast_udp_sock_tup = tuple({multicast_udp_sock})
    thread_udp = threading.Thread(target=listen_for_multicasts,
                              args=(multicast_udp_sock,)
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
            send_multicast(my_udp_socket_obj)

def listen_for_multicasts(multicast_udp_sock):
    while True:
        # Receive data from the socket
        data, partner_socket_tuple = multicast_udp_sock.recvfrom(1024)
        print(f'Received packet from {partner_socket_tuple}: {data.decode('utf-8')}')    
        #respond by setting up TCP connection.
        my_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket_obj.connect(partner_socket_tuple)

def send_multicast(my_udp_socket_obj):
    message = 'hello'
    try:
        print(f'{MULTICAST_UDP_IP}, {MULTICAST_UDP_PORT}, {message}')
        my_udp_socket_obj.sendto(message.encode(),
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