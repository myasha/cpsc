"""
Author: Myasha Berman
File: receiver.py

Purpose:
Establishes a TCP receiver to simulate and log network issues like packet loss 
and corruption during message transfers, while running continuously on a fixed
port. 

Note: the slides talk about deleting duplicates for 3.0 but that is not 
      implemented in this version per the instructions. 
"""

from socket import *
from time import sleep
import util

# No other imports allowed

class PreviousACK:
    """A class to store the previous ACK value
     
    Attributes: 
       prev_ack (packet): the previous ACK packet    
    """

    def __init__(self):
        """Initializes a new PreviousACK instance with a packet"""

        # Previous packet initialized to 1, 1 
        # ACK = 1 means indicates this packet is an ACK 
        self.previous_ack = util.make_packet("", 1, 1)

    def set_prev_ack(self, new_ack):
        """Updates the previous ack value to new a sequence number
        
        Args:
        - new_ack (packet): The new ACK packet to be set as the previous ACK. 
        """
        
        # Update the new value and store it 
        self.previous_ack = new_ack

    def get_prev_ack(self):
        """Returns the current value of the previous ack."""
        return self.previous_ack
    

class PacketCounter:
    """A class to count packets.

    Attributes:
        counter (int): The number of packets counted.
    """

    def __init__(self):
        """ Initializes a new PacketCounter instance with the counter set 
            to one.
        """
        self.counter = 0

    def increment(self):
        """Increments the counter by one."""
        self.counter += 1
 
    def get_count(self):
        """Retrieves the current count of packets.

        Returns:
            int: The current packet count.
        """
        return self.counter
    
def main():
    """  
    Initializes a TCP socket on a fixed port, handles client requests with
    simulated network issues, and manages packet acknowledgments. Continuously 
    runs until an interruption occurs. 
    """

    # Set the port number and open the connection 
    port_number = 10559
    server_socket = open_connection(port_number)

    # Create a packet counter object & place to store prev. ACK
    packet_counter = PacketCounter()
    prev_ack = PreviousACK()

    # Loop until connection is interrupted 
    try:
        server_loop(server_socket, packet_counter, prev_ack)
    except KeyboardInterrupt:
        close_connection(server_socket)


def server_loop(server_socket, packet_counter, prev_ack):
    """
    Runs an infinite loop to accept and handle client connections on the given 
    server socket. Processes incoming data through 'handle_sender_data'
    function. Continues until manually interrupted.

    Args:
        server_socket (socket): The socket object on which the server listens
                                listening for incoming connections.
    """

    # Loop and handle until interrupt (graceful exit)
    while True:
        
        # Print status to console and accept connections
        conn_socket, addr = server_socket.accept()
    
        # Handle client requests here 
        handle_sender_data(conn_socket, packet_counter, prev_ack)


def open_connection(server_port):
    """ 
    Creates, binds, and listens on a new server socket using the 
    provided port number.
    
    Args: server_port: the port number used for connecting to client 
    """

    # Make new server socket and set for reuse 
    new_server_socket = socket(AF_INET, SOCK_STREAM)
    new_server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    # Bind and listen 
    new_server_socket.bind(('', server_port))
    new_server_socket.listen(1)

    # Return newly created socket 
    return new_server_socket


def close_connection(server_socket):
    """Closes the socket connection
    
    Args: server_socket, the connection to close 
    """
    server_socket.close()


def handle_sender_data(conn_socket, packet_counter, prev_ack):
    """
    Receives data packets from a connection socket and processes them, 
    sending ACKs for each.

    Args:
        conn_socket (socket): The socket object for client communication.
        packet_counter (int): The current count of packets processed.
    """   
    # Get the packet and print confirmation 
    get_packet = conn_socket.recv(1024)
    
    # Increase the packet count 
    packet_counter.increment()

    # Print status to console 
    print(f'packet num.{packet_counter.get_count()} received: {get_packet}')

     # Write packet to file
    save_to_file(get_packet)

    # Get handling status
    handling_status = get_handling_status(get_packet, packet_counter)
    
    # Print correct status of packet (successful, sleep, corrupt)
    print_msg(handling_status, get_packet)

    # Send ACK 
    send_ack(get_packet, conn_socket, packet_counter, handling_status, prev_ack)
   

def get_handling_status(packet, packet_counter):
    """
    Checks packet for initial data corruption. If ok, simulates 
    network issues in two ways: 
    - Divisible by six: sleep
    - Divisible by three (and not six): corruption 

    Args: 
    - packet: the packet of data sent from sender
    - packet counter: an integer representing the number of packets
      received 
    """

    # Verify checksum (data corruption check)
    if not util.verify_checksum(packet):
        return "corrupt"   
    
    # Simulate packet loss & sleep
    elif is_lost(packet_counter):
        return "sleep"
    
    # Simulate corruption status
    elif is_corrupt(packet_counter):
        return "corrupt"  
    
    # Return successful packet status (packet = good)
    else:
        return "successful"  
    

def save_to_file(packet):

    """
    Appends the given binary data to 'received_pkt.txt' file as a string

    Args:
        packet (bytes): The byte data to be appended to the file.
    """
    
    with open('received_pkt.txt', 'a') as file:
        # Convert the bytes to a string representation with b'...'
        packet_str = repr(packet)
        # Write the string representation to the file
        file.write(f"{packet_str}\n")


def handle_default(packet):
    """Return expected message and delivery status after extracting payload
    
    Args:
    - msg_str (string): the data (payload) from the packet 
    """

    # Get the data 
    payload = get_payload(packet)
    
    # Return message 
    return f"packet is expected, message string delivered: {payload}"

def handle_status_1():
    """Return message indicating simulation of packet loss"""
    return (f"simulating packet loss: sleep a while to trigger timeout "
            "event on send side...")

def handle_status_0():
    """Return message indicating simulation of data corruption"""
    return "simulating bit errors/corrupted: ACK the previous packet!"

def print_msg(packet_status, packet):
    """
    Prints the correct response message depending on the real or simulated
    network issue. 

    Args:
    - packet (bytes): the byte data from the message
    - packet_status (int): the integer used to print correct response
    - 
    
    """
    if packet_status == "corrupt":
        status_message = handle_status_0() # Data corruption
    elif packet_status == "sleep":
        status_message = handle_status_1() # Packet loss (sleep)
    else:
        status_message = handle_default(packet)  # Successful transmission 
    
    # Print correct status message 
    print(f"{status_message}")


def send_ack(packet, conn_socket, packet_counter, handling_status, prev_ack):
    """
    Sends ACK to the sender. If the packet is corrupt or lost,
    resend the previous ACK. If the packet is successfully received,
    send an ACK with the received sequence number.

    Args: 
    -
    """
    
    # Simulate data corruption
    if handling_status == "corrupt": 
        
        # Resend the previous ACK response
        ack_response = prev_ack.previous_ack

    # Respond like normal for "success"
    else:   
        # Extract ACK and SEQ numbers from the packet
        seq_num = get_seq_number(packet)
        
        # Make the packet with the same SEQ number for ACK
        # ACK = 1 to indicate it's an ACK packet 
        ack_response = util.make_packet("", 1, seq_num)
        
        # Store the new ack as the previous ack in case the next packet is bad
        prev_ack.set_prev_ack(ack_response)

        if handling_status == "successful":

            # For successful packet reception
             print('packet is delivered, now creating and sending the ACK packet...')

        elif handling_status == "sleep":
             sleep(1)      
        
    # Send the ACK packet & print confirmation 
    conn_socket.send(ack_response)
    print("all done for this packet!\n")

    # Do not close connection: wait for new packet and repeat process
    if handling_status == "corrupt" or handling_status == "sleep":

        # Because connection is kept open
        handle_sender_data(conn_socket, packet_counter, prev_ack)
     
def get_seq_number(packet):
    """
    Extracts the sequence number from the packet. Assumes that the sequence
    number is the 16th bit of the packet in the 12th byte.

    Args:
        packet (bytes): The received packet.

    Returns:
        seq_num (int): A number (0/1) indicating the packet's sequence number
    """
   
    # Grabbing the 12th byte from the packet
    byte_index = 11   # Index for 12th byte 

    # Extract the 12th byte
    the_byte = packet[byte_index]  

    # Extract the 16th bit (2nd bit of the 12th byte)
    seq_num = the_byte & 1

    # Return tuple
    return seq_num

def get_payload(packet):
    """
    Extracts the payload from the packet starting after the 16th byte.

    Args:
        packet (bytes): The packet from which the payload is to be extracted.

     Returns:
        str: The payload of the packet as a UTF-8 encoded string.
    """
    
    # The payload starts after the 16th byte, so the slice starts at index 15
    payload = packet[12:]
    
    # Decode the payload to string using UTF-8 encoding
    try:
        return payload.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("The payload could not be decoded to a \
                         string using UTF-8 encoding.") 

def is_corrupt(packet_number):
    """Determines if the received packet is corrupt. This is calculated by
       taking the packet number % 3 == 0 
       
       Args:
       packet_number(int): The object counter that adds the number of packets
                           received   
    """
    # Returns true if divisible by 3 
    return packet_number.get_count() % 3 == 0

def is_lost(packet_number):
    """Determines if the received packet was lost in transit. This is
    calculated by taking the packet number % 6 == 0
    
    Note: in the event of a tie (divisible by 3 and 6), this condition
          supersedes corruption so the packet simulates a timeout instead
          of corruption.

    Args: `
    - packet_number (int): The object counter that adds the number of packets
                           received 
    """

    # If the number is divisible by 6
    return packet_number.get_count() % 6 == 0

def toggle_number(number):
    """Toggles between 0 and 1 depending on input

    Args:
    - number (int): the value to toggle between 0 and 1 

    """
    return number ^ 1
    
if __name__ == "__main__":
    main()