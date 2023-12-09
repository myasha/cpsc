"""
Author: Myasha Berman
File: util.py

The utility functions for the receiver.py and sender.py files that
calculates checksums, checks checksums, and creates packets. 

"""

def create_checksum(packet_wo_checksum):
    """create the checksum of the packet (MUST-HAVE DO-NOT-CHANGE)

    Args:
      packet_wo_checksum: the packet byte data (including headers except for checksum field)

    Returns:
      the checksum in bytes
    """

    # Pad with 0 if length isn't even 
    if len(packet_wo_checksum) % 2 != 0:
        packet_wo_checksum += b'\x00'

    checksum  = 0

     # Initialize the checksum to zero
    checksum = 0

    # Sum up the 16-bit words
    # (Loop length of packet in steps of 2)
    for i in range(0, len(packet_wo_checksum), 2):
        
        #16-bit word is constructed from two adjacent bytes of the packet.
        word = (packet_wo_checksum[i] << 8) + packet_wo_checksum[i+1]

        # Add the words together
        checksum += word

        # Makes sure checksum does not exceed 16 bits 
        checksum = (checksum & 0xFFFF) + (checksum >> 16)  # Add carry

    # Invert the bits to get the one's complement
    checksum = ~checksum & 0xFFFF

    # Return the checksum as a byte sequence
    return bytes([(checksum >> 8) & 0xFF, checksum & 0xFF])


def verify_checksum(packet):
    """verify packet checksum (MUST-HAVE DO-NOT-CHANGE)

    Note: For assignment data will NOT be more than 1,000 bytes 

    Args:
      packet: the whole (including original checksum) packet byte data

    Returns:
      True if the packet checksum is the same as specified in the checksum field
      False otherwise

    """

    # Extract the original checksum from the packet
    original_checksum = packet[8:10]

    # Replace the checksum field in the packet with zeros 
    packet_wo_checksum = packet[:8] + b'\x00\x00' + packet[10:]

    # Calculate the checksum on the modified packet
    calculated_checksum = create_checksum(packet_wo_checksum)

    # The packet is correct if the calculated checksum matches original
    return calculated_checksum == original_checksum


def make_packet(data_str, ack_num, seq_num):
    """
    Create and return a network packet with a given data string, ACK number, 
    and sequence number.
    
    Args:
        - data_str (str): The payload data to be encapsulated in the packet.
        - ack_num (int): Acknowledgement flag bit (0 or 1) to indicate packet 
                         acknowledgment.
        - seq_num (int): Sequence flag bit (0 or 1) to indicate the sequence
                         number of the packet.
    
    Returns:
        bytes: The constructed network packet ready for transmission.
    """
    # Constants
    HEADER_IDENTIFIER = b"COMPNETW"  # First 8 bytes
    HEADER_SIZE = 12  # Size of the header in bytes

    # Convert string to bytes
    data_bytes = data_str.encode('utf-8')

    # Calculate packet length (header + data)
    # Note: per assignment we are assuming length of data is < 1000 bytes 
    packet_length = HEADER_SIZE + len(data_bytes)

    # Mask to ensure only 14 bits for length
    packet_length &= 0x3FFF

    # Shift left by 2 bits to make room for flags
    length_and_flags = packet_length << 2  

    # Set the second-to-last bit for ACK and the last bit for SEQ
    length_and_flags |= (ack_num << 1)
    length_and_flags |= seq_num         

    # Convert length_and_flags to bytes
    length_and_flags_bytes = length_and_flags.to_bytes(2, 'big')

    # Prepare a placeholder for checksum (will be calculated later)
    checksum_placeholder = b'\x00\x00'

    # Construct the packet without the checksum
    packet_without_checksum = (HEADER_IDENTIFIER + checksum_placeholder +
                               length_and_flags_bytes + data_bytes)

    # Get checksum and calculate new packet 
    checksum  = create_checksum(packet_without_checksum)
    packet_with_checksum = (HEADER_IDENTIFIER + checksum +
                               length_and_flags_bytes + data_bytes)

    
    # Return the finished packet, phew! 
    return packet_with_checksum



###### These three functions will be automatically tested while grading. ######
###### Hence, your implementation should NOT make any changes to         ######
###### the above function names and args list.                           ######
###### You can have other helper functions if needed.                    ######  