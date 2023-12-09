"""
Author: Myasha Berman
File: sender.py

Manages reliable data transmission over a network using a custom protocol. It
handles socket connections, packet sending, ACK reception, and maintains
sequence numbers for communication integrity.
"""

from socket import *
import util

class Sender:
    """
    Manages reliable network data transmission using a custom protocol. 
    Handles connection, packet dispatch, and ACK handling with sequence
    number tracking.

    Attributes:
        seq_num (int): Sequence number for sent packets.
        ack_num (int): Expected ACK number, fixed at 0 for sender.
        packet_number (int): Count of packets sent.
    """

    def __init__(self):
        """ 
        Your constructor should not expect any argument passed in,
        as an object will be initialized as follows:
        sender = Sender()
        
        Please check the main.py for a reference of how your function will be called.
        """

        # Set initial values  
        self.seq_num = 0        # Instance variable for the sequence number
        self.ack_num = 0        # ACK from sender will always be 0 
        self.packet_number = 0  # Instance variable for the packet number


    def rdt_send(self, app_msg_str):
        """reliably send a message to the receiver (MUST-HAVE DO-NOT-CHANGE)

        Args:
        app_msg_str: the message string (to be put in the data field of the packet)

        Note: Ideally, I might want to keep a TCP connection open for all the
              transfers but I'm going to do it per string message for sake of
              ease managing the connection from here. 
        """
        
        # Increase the packet number counter 
        self.packet_number += 1
        
        # Connect to the socket 
        client_socket = self.connect_socket()

        # Print original message
        print('\noriginal message string:', app_msg_str)

        # Make a packet and dummy packet for comparing received ACKs 
        packet = util.make_packet(app_msg_str, self.ack_num, self.seq_num)

        # In expected packet, ACK = 1 to indicate it's an ACK 
        expected_ack = util.make_packet("", 1, self.seq_num)
        
        # Print confirmation 
        print('packet created: ', packet)

        # Run send, wait for ack, retransmit if necessary 
        self.run_send(packet, client_socket, expected_ack, app_msg_str)     

        # Decrement or increment seq_num depending on previous value  
        self.seq_num = self.toggle_number(self.seq_num)

        # Close the connection (yes, probably inefficient)
        client_socket.close()


    def run_send(self, packet, client_socket, expected_ack, msg):
        """
        Sends a packet to a client and handles ACKs for up to five retries on
        failure.
        Prints status messages and manages retransmissions and timeouts.

        Args:
        - packet (bytes): Data packet to send.
        - client_socket (socket.socket): Socket for sending the packet.
        - expected_ack (bytes): Expected ACK response.
        - msg (str): Message for retransmission alerts.
        """

        retries = 0        # Set retries count to 0
        max_retries = 3    # Max tries allowed
        packet_sent_successfully = False # Set to false because nothing sent 
        is_retransmission = False # Set to false because no transmission yet 
        is_timeout = False # Set to false because no timeout events yet 

        # Loop to send and process responses from the receiver
        # Loop ends when package sent successfully or after 5 attempts  
        while retries < max_retries and not packet_sent_successfully:
            
            # Try-catch for timeout 
            try:  
                # If retransmission: send output alerting resend 
                if is_retransmission == True:
                    print(f'[ACK-Previous transmission]: {msg}')
                    
                    # Reset 
                    is_retransmission = False

                if is_timeout == True: 
                    print(f'[Timeout Retransmission]: + {msg}')

                    # Reset 
                    is_timeout = False

                # Send packet to receiver and start a timer 
                self.send_packet_start_timer(packet, client_socket) 

                # Print sent confirmation
                print(f'packet num. {self.packet_number} is ' \
                        ' successfully sent to the receiver.')       

                # Get client response & process (note: not expecting > 1024)
                receiver_response = client_socket.recv(1024)

                # If True resend the packet/restart timer
                if self.should_resend_packet(receiver_response, expected_ack):

                    # Flag it as retransmission  
                    is_retransmission = True
                        
                    print('receiver acked the previous pkt, resend!\n')
                    retries += 1
                    self.packet_number += 1
        
                else:
                    # Get sequence number from the received ACK 
                    ack_receiver_num = self.get_seq_num(receiver_response)

                    # Set this to True to exit the loop 
                    # (seq = received ack but using *sender* values for output)
                    print(f'packet is received correctly: seq num {self.seq_num}' \
                        f' = ACK num {ack_receiver_num}. All done!') 
                    
                    packet_sent_successfully = True  

            except timeout:
                
                # Set timeout bool to output correct statement to console 
                is_timeout = True
                self.packet_number +=1 
                retries += 1
                print('socket timeout! Resend!\n')


    def send_packet_start_timer(self, packet, client_socket):
        """
        Sends a packet and sets a timeout for the response.

        Args:
        - packet (bytes): Packet to send.
        - client_socket (socket.socket): Socket to use for sending.
        """

        # Send to the client and  
        client_socket.send(packet)
        client_socket.settimeout(1)


    def print_confirmation_response(self, seq_number, ack_number):
        """
        Prints the status of the correct SEQ and ACK confirmation

        Args:
        - seq_number: sequence number 0 or 1
        - ack_number: ack number 0 or 1 
        """
        
        # Print response to console 
        print(f'packet is received correctly: seq. num {seq_number} = '
              f'ACK num {ack_number}. All done!\n')
        
    
    def should_resend_packet(self, receiver_response, expected_ack):
        """
        Args: 
        - receiver_response (bytes): the ACK from the receiver 
        - expected_response (bytes): the expected ACK response

        Returns:
        - True if the received response matches the expected response
        """

        # Verify checksum 
        if util.verify_checksum(receiver_response):

           # If valid: check response to see if seq. nums match in the packet
           return not receiver_response == expected_ack
               
        # Otherwise, return false 
        return True
    
        
    def connect_socket(self):
        """
        Connects to the receiver through hardcoded ip/port values

        Returns:
        - client_socket (socket): the connected client socket 
        """
        
        # Connect to CS1 with CS1 IP and student hash
        server_ip = '127.0.0.1' 
        server_port = 10559

        # Create socket: specify IP address family and transport
        client_socket = socket(AF_INET, SOCK_STREAM)
        client_socket.connect((server_ip, server_port))

        return client_socket
    

    def toggle_number(self, number):
        """Toggles between 0 and 1 depending on input

        Args:
        -number (int): the value to toggle between 0 and 1 
        """
        return number ^ 1
    
    
    def get_seq_num(self, ack_packet):
        """
        Extracts the sequence number from the ACK packet.

        This method retrieves the sequence number by extracting the second bit 
        of the 12th byte from the given packet, which represents the sequence 
        number.

        Args:
        - ack_packet (bytes): The ACK packet received.

        Returns:
        - int: The extracted sequence number from the ACK packet.
        """
        
        # Grabbing the 12th byte from the packet
        byte_index = 11   # Index for 12th byte 

        # Extract the 12th byte
        the_byte = ack_packet[byte_index]  

        # Extract the 16th bit (2nd bit of the 12th byte)
        receiver_seq_num = the_byte & 1

        return receiver_seq_num