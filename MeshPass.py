# MeshPass
''' Password manager with record sharing with other users

MeshPass is a password manager program.
It allows syncing of all records with other devices owned
by the same user.
It also allows one-way syncing of selected records with other users.
'''

import socket
import struct
import threading
from cryptography.hazmat.primitives            import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf   import HKDF
from cryptography.fernet                       import Fernet

# Define the UDP IP address and port to listen on
MULTICAST_UDP_IP    = '224.0.0.86'
MULTICAST_UDP_PORT  = 5005
MULTICAST_TUPLE     = (MULTICAST_UDP_IP, MULTICAST_UDP_PORT)
MULTICAST_TTL_LIMIT = 1
RCV_BFR_SZ          = 1024


HEADER_LEN    = 64
FORMAT        = 'utf-8'
MYHOSTNAME    = socket.gethostname()
MY_IP_ADDRESS = socket.gethostbyname(MYHOSTNAME)
MY_TCP_PORT   = 5051
UNICAST_UDP_PORT = 5052
UNICAST_TUPLE = (MY_IP_ADDRESS, UNICAST_UDP_PORT)

MY_SOCKET_TUPLE           = (MY_IP_ADDRESS, MY_TCP_PORT)
CLIENT_SOCKET_TUPLE       = ()
DISCONNECT_MESSAGE        = "!DISCONNECT"
KEY_EXCHANGE_MESSAGE      = '!KEY_EXCHANGE'
PARAMETER_REQUEST_MESSAGE = '!PARAMETER_REQUEST'
KEY_MATERIAL_READY        = '!KEY_MATERIAL_READY'
PARAMETERS_RESPONSE       = '!PARAMETERS_RESPONSE'


def main(cli_args):
    print(f'Listening for UDP packets'
          f' on {MULTICAST_UDP_IP}:{MULTICAST_UDP_PORT}')
    print(f"my host name: {MYHOSTNAME}")
    print(f"my ip address: {MY_IP_ADDRESS}")

    found_devices = []

    # Create multicast socket to listen for other MeshPass devices on LAN
    multicast_listen_udp_socket_obj = socket.socket(socket.AF_INET,
                                                    socket.SOCK_DGRAM,
                                                    socket.IPPROTO_UDP)
    # REUSEPORT helps when restarting app & OS thinks socket is still open.
    multicast_listen_udp_socket_obj.setsockopt(socket.SOL_SOCKET,
                                               socket.SO_REUSEPORT, 1)
    
    # IP_ADD_MEMBERSHIP supposedly needed to receive multicasts.
    # Possibly, this function really enables IGMP report messages.
    # Should address in this option be INADDR_ANY or MULTICAST_UDP_IP ?
    mreq = struct.pack('4sl',
                       socket.inet_aton(MULTICAST_UDP_IP),
                       socket.INADDR_ANY)
    multicast_listen_udp_socket_obj.setsockopt(socket.IPPROTO_IP,
                                               socket.IP_ADD_MEMBERSHIP,
                                               mreq)

    #multicast_listen_udp_socket_obj.bind(MULTICAST_TUPLE)

    unicast_socket_obj = socket.socket(socket.AF_INET,
                                       socket.SOCK_DGRAM,
                                       socket.IPPROTO_UDP
                                      )

    unicast_socket_obj.bind(UNICAST_TUPLE)

    # Time-To-Live is 1 because multicast packets can't traverse router anyway.
#    multicast_send_udp_socket_obj = socket.socket(socket.AF_INET,
#                                                  socket.SOCK_DGRAM,
#                                                  socket.IPPROTO_UDP)
#    multicast_send_udp_socket_obj.setsockopt(socket.IPPROTO_IP,
#                                             socket.IP_MULTICAST_TTL,
#                                             MULTICAST_TTL_LIMIT)

    #set up TCP server socket to listen for sync requests
    my_socket_obj = socket.socket(socket.AF_INET,
                                  socket.SOCK_STREAM)  # create TCP socket
    my_socket_obj.bind(MY_SOCKET_TUPLE)  # bind socket to address and port

    #server_socket_obj.listen()
    #multicast_listen_udp_socket_obj_list = [multicast_listen_udp_socket_obj]
    #multicast_listen_udp_socket_obj_tup = tuple({multicast_listen_udp_socket_obj})
    thread_udp = threading.Thread(target=listen_for_multicasts,
                                  args=(multicast_listen_udp_socket_obj, unicast_socket_obj)
                                 )
    thread_udp.start()

    thread_unicast = threading.Thread(target=listen_for_unicast,
                                      args=(unicast_socket_obj, found_devices)
                                     )
    thread_unicast.start

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
            send_multicast(unicast_socket_obj)
        elif command == 'EXIT':
            multicast_listen_udp_socket_obj.close()
            unicast_socket_obj.close()
            my_socket_obj.close()
            print(f'exit')
            return 0
        elif command == 'CHOOSE':
            for row, device in enumerate(found_devices):
                print(f'USERNAME: {device.user_name}: {row}')
                selected_row = input().upper
                if int(selected_row) < found_devices.len():
                    selected_device = found_devices[int(selected_row)]
                    attempt_sync(selected_device, my_socket_obj)

#add code so that found devices cannot change during choosing

class MeshPassDevice:
    def __init__(self):
        device_id = None
        user_id = None
        user_name = None
        public_key = None
        ip = None
        port = None

def attempt_sync(target_device, my_socket_obj):
    target_tuple = (target_device.ip, target_device.port)
    my_socket_obj.connect(target_tuple)


def listen_for_unicast(unicast_socket_obj, found_devices):
    while True:
        data, partner_socket_tuple = unicast_socket_obj.recvfrom(RCV_BFR_SZ)
        message = data.decode(FORMAT)
        message_parts = message.split(':')
        if message_parts[0] == 'IM HERE':
            device_id  = message_parts[1]
            user_id    = message_parts[2]
            user_name  = message_parts[3]
            public_key = message_parts[4]
            ip, port   = partner_socket_tuple
            print(f'USERNAME: {user_name}')
            device_already_found = False
            for device in found_devices:
                if device_id == device.device_id and user_id == device.user_id:
                    device_already_found = True
                    break
            if not device_already_found:
                new_device = MeshPassDevice()
                new_device.device_id = device_id
                new_device.user_id = user_id
                new_device.user_name = user_name
                new_device.public_key = public_key
                new_device.ip = ip
                new_device.port = port
                found_devices.append(new_device)

        elif message_parts[0] == 'I CHOOSE YOU':
            partner_ip_address = message_parts[1]
            partner_port = message_parts[2]
            partner_socket_obj = socket.socket(socket.AF_INET,
                                               socket.SOCK_STREAM)  # create TCP socket
            partner_socket_obj.bind(MY_SOCKET_TUPLE)  # bind socket to address and port
            

def listen_for_multicasts(multicast_listen_udp_socket_obj, unicast_socket_obj):
    while True:
        # Receive data from the socket
        data, partner_socket_tuple = multicast_listen_udp_socket_obj.recvfrom(RCV_BFR_SZ)
        message = data.decode(FORMAT)
        if message.split(':')[0] == MY_IP_ADDRESS:
            print(f'{partner_socket_tuple}: This is me.')
            return
        print(f'Received packet from {partner_socket_tuple}: {message}')    
        print(f'{MY_IP_ADDRESS}')
        #respond by setting up TCP connection.
        #respond by saying "i'm here"
        response = f'IM HERE:<device id>:<user id>:<user name>:<public key>'
        unicast_socket_obj.sendto(response.encode(), partner_socket_tuple)


        #my_socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # need Global m_s_o; need skt.bind
        #my_socket_obj.connect(partner_socket_tuple)                        # better, pass m_s_o thru func args

#Who's out there?
def send_multicast(unicast_socket_obj):
    message = f'{MY_IP_ADDRESS}:{UNICAST_UDP_PORT}'
    try:
        unicast_socket_obj.sendto(message.encode(),
                             (MULTICAST_UDP_IP, MULTICAST_UDP_PORT)
                            )
        print(f'Sent UDP packet to {MULTICAST_UDP_IP}:'
              f'{MULTICAST_UDP_PORT}\nMESSAGE: {message}')
    except:
        print(f'exception')

def listen_for_tcp(my_socket_obj):
    my_socket_obj.listen()
    while True:
        partner_socket_obj, partner_ip_address = my_socket_obj.accept()
        print(f"type of conn: {type(partner_socket_obj)}")
        thread = threading.Thread(target=handle_incoming_call,
                                  args=(partner_socket_obj,
                                        partner_ip_address))
        print(f"type of thread: {type(thread)}")
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count()-1}")



#print("[STARTING] server is starting...")


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))