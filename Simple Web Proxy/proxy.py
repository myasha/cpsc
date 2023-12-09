"""
Author: Myasha Berman
File:   proxy.py
Overview: 

proxy.py is a straightforward web proxy server script. Upon execution, it 
initializes a socket, binds it to a specific address, and waits for incoming 
web requests. When a request is received, it determines the target destination 
and routes the request accordingly. The script also handles the response, 
capturing it from the target server and relaying it back to the original 
requester. Features include potential caching for faster response times.
"""

from socket import *
from urllib.parse import urlparse
import sys
from pathlib import Path

def main():
    """ 
    Usage:
    Main point of entry for the simple proxy server/cache application. 
    Invoke when starting the proxy server. Creates a default server port
    from command line arguments and enters a loop to handle client requests.
    
    Note:
    Assumes command-line port (if used) is valid. No error handling for 
    invalid or missing port number.
    """ 
    # Create the socket and enter in a listening loop to handle client requests
    # Assuming the command line is entered validly per discussion in class 
    server_port = int(sys.argv[1])
    server_socket = create_socket(server_port)

    try:
        server_loop(server_socket)
    except KeyboardInterrupt:
        handle_shutdown(server_socket)

def server_loop(server_socket):
    """
    Continuously listens for and handles client requests on the given server 
    socket.

    The loop can be interrupted using an interrupt command. Each incoming
    client request is delegated to the 'handle_client_request' function.

    Parameters:
        - server_socket (socket): The socket on which the server listens for 
                                  incoming client connections.
    """
    while True:
        print("************ Ready to serve... ************")
        conn_socket, addr = server_socket.accept()
        print(f'Received a client connection from: {addr}')
        handle_client_request(conn_socket)

def handle_shutdown(server_socket):
    """
    Usage: 
    Gracefully shuts down the proxy server.
    
    Parameters:
    - server_socket(socket): The socket on which the proxy server is listening.
    """
    # Output action to console and close the socket 
    print("\nShutting down the proxy server...")
    server_socket.close() 
    

def create_socket(server_port):   
    """
    Usage: 
    Creates, configures, and returns a new TCP server socket bound to the 
    provided port and listens on it for incoming connections.
    
    Parameters:
    - server_port (int): The port number to which the created socket
                         is bound  
    """
     
    # 1. Create Socket (IP/port #) 2. set for reuse 3. bind 4. listen 
    new_server_socket = socket(AF_INET, SOCK_STREAM)
    new_server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) 
    new_server_socket.bind(('', server_port))
    new_server_socket.listen(1)
    
    return new_server_socket  

def handle_client_request(conn_socket):
    """
    Usage: 
    Handles the incoming GET request from a client, processes it, 
    and sends back the appropriate response. Closes the client socket 
    after handling the request. 
    
    Parameters:
    - conn_socket (socket): The connection socket for the client's request.
    
    Note:
    - Assumes the incoming data from the client is a GET request.
    - Errors encountered during request handling are logged, and the client 
    socket is closed regardless of errors. 
    """ 
    try:
        # Receive the GET request from the client
        get_request_bytes = conn_socket.recv(1024)

        # Output message to console (log) / handle GET request + response
        print('Received a message from the client:', get_request_bytes)
        response = process_get_request(get_request_bytes)
        
        # Output status to console and send the response to the client
        print ("Now responding the client...")
        conn_socket.send(response.encode())

    # Catch any errors and output error to console 
    except Exception as e:
        print(f'Error handling client request: {e}')
    finally:
        # Close the client socket
        print('All done! Closing the socket...')
        conn_socket.close()

def process_get_request(get_request_bytes):
    """
    Usage: 
    Processes the incoming GET request (bytes to string), retrieves the
    requested content either from the cache or the server, and constructs 
    an appropriate response to send back to the client. 
    
    Parameters:
    - get_request_bytes (bytes): The raw GET request from the client.
    
    Returns:
    - response (str): The constructed response for the client based on 
                      the GET request.
    
    Note:
    - Assumes that the incoming data is a GET request. 
    - The function handles both valid and invalid requests, and it will 
      build an appropriate response for each.
    """
    
    # Verify GET request is properly formatted
    get_request_str = get_request_bytes.decode()

    if not verify_get_request(get_request_str):
        print("Invalid HTTP request line")
        return build_client_response('Unsupported Error', 
                                     False, '500 Internal Error')

    # Parse GET request 
    host, path, port = parse_get_request(get_request_str)

    # Validate URL
    if not validate_url(host, path, port):
        print('Invalid URL')
        return build_client_response('Unsupported Error', False,
                                     '500 Internal Error')

    # Attempt to fetch from cache (or server if needed)
    status_code, cache_hit, content = get_from_cache(host, path, port)

    # Build and return the client response
    return build_client_response(status_code, cache_hit, content)

def verify_get_request(get_request):  
    """
    Usage: 
    Verifies that the input string adheres to the HTTP 1.1 GET request format.
    The function expects the format to be: <METHOD> <URL> <HTTP VERSION>.
    It checks for an exact match with the method "GET" and version "HTTP/1.1".

    Parameters:
    - get_request (str): The input string representing the GET request.

    Returns:
    - bool: True if the input matches the expected GET request format. 
            Otherwise, returns False. This includes scenarios where the input 
            cannot be split into three parts or if the method/version doesn't 
            match the expected values.
    """

    # Attempt to parse into 3 strings
    # <METHOD> <URL> <HTTP VERSION> 
    try:
         method, url, version = get_request.split(" ")
    except ValueError:
        return False

    return method == "GET" and version.strip() == "HTTP/1.1"

def validate_url(host, path, port):
    """
    Usage:
    Validates the components of a URL to ensure proper formatting 
    before further operations such as fetching or caching.
    
    Parameters:
    - host (str): The host component of the URL.
    - path (str): The path component of the URL.
    - port (int): The port component of the URL.
    
    Returns:
    - bool: True if all URL components are valid, otherwise False.
    """ 
    # Validate host, port, and path, and return bool 
    is_host_valid = bool(host and isinstance(host, str))
    is_port_valid = bool(port and isinstance(port, int) 
                         and (0 < port <= 65535))
    is_path_valid = bool(path and isinstance(path, str))
    
    return all([is_host_valid, is_port_valid, is_path_valid])

def parse_get_request(get_request_to_parse):
    """
    Usage:
    Extracts the host, path, and port from a standard HTTP GET request.

    Parameters:
    - get_request_to_parse (str): The GET request string to parse.

    Returns:
    - tuple: (host, path, port)
        - host (str): The extracted host from the URL.
        - path (str): The extracted path from the URL.
        - port (int): The extracted port from the URL or 80 if missing.
      If any component is invalid or missing, the corresponding value in 
      the tuple will be None.
    """
    # Get the URL <METHOD><URL><HTTP VERSION> if none: return NONE
    try:
        _, url, _ = get_request_to_parse.split(" ")
    except ValueError:
        return None, None, None

    # Parse URL
    parsed_url = urlparse(url)

    # Parse the URL: extract host, port, path (80 if missing)
    host = parsed_url.hostname
    port = parsed_url.port if parsed_url.port else 80  
    path = parsed_url.path

    return host, path, port
                  
def get_from_cache(host, path, port):
    """
    Usage:
    Retrieves content from the local cache or fetches it from a remote server 
    if absent. On cache miss or if the cached content exceeds a certain size, 
    the data is fetched from the remote server and possibly updated in the 
    cache based on the response status.

    Parameters:
    - host (str): The hostname or IP address.
    - path (str): The path from the URL.
    - port (int): The port number.

    Returns:
    - content (str or bytes): The content to be sent to the client.
    - cache_hit (bool): Indicates if the content was retrieved from the cache.
    - status_msg (str): Status message for the response.

    Note: 
    - Cache management, like eviction policies or freshness checks, are not 
      handled in this version of the function for simplicity.
    """
    
    # Variable Declaration
    # Port number added to path for more comprehensiveness 
    cache_path = Path('.cache') / str(host) / str(port) / str(path).lstrip('/')
    MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

    try:
       
       #Look for the file in the cache using the path. If we find: 
        if cache_path.exists() and cache_path.stat().st_size <= MAX_FILE_SIZE:
            print('Yeah! The requested file is in the cache and is about to be'
                'sent to the client!')
            
            # Open up the cache and read 
            with open(cache_path, 'rb') as f:
                content = f.read()
                content_str = content.decode('utf-8')  
        # Check if the variable has been assigned a non-empty value
        if content_str:  
            return content_str, True, '200 OK'
        else:
            raise Exception('Oops! No cache hit! Requesting origin server' 
                            'for the file...')
    except Exception as e:
        print(f"An error occurred while reading from cache: {str(e)}")

    # Cache miss: fetch, save, and signal cache miss
    remote_data = connect_to_remote_server(host, path, port)
   
    # Get the header for the status code
    headers, content = split_response_data(remote_data)
    status_code = get_status_code(headers)
    
    # Not in cache: Respond appropriately depending on header 
    if status_code == 200:
        print('Response received from server, and status code is 200. '
               'Write to cache, save time next time...')
        save_to_cache(content, host, path, port)
        return content.decode('utf-8'), False, '200 OK'
    
    else:
        print("Response received from server, but status code is not 200!"
              "No cache writing....")
        
    if status_code == 404:
        content = "404 NOT FOUND"
        return '\n404 Not Found', False, content
    else: 
        content = "\nUnsupported Error"
        return '500 Internal Error', False, content

def save_to_cache(cache_data, host, path, port):
    """
    Usage: 
    This function is used after fetching data that isn't already in
    the cache. This ensures that the fetched data is saved for faster
    subsequent retrieval. Note:

    Parameters:
    - cache_data (str or bytes): The retrieved data to be cached.
    - host (str): The hostname or IP address used as a part of the cache
      directory.
    - path (str): The path from the URL, which will be used as the
                  filename within the cache directory.
    Note: 
    - For the scope of this project, advanced features such as an eviction
      policy for the cache (e.g., FIFO, LIFO) and freshness checks (data age) 
      have been intentionally omitted for simplicity.
    """

    # 1. Build the file path within the cache directory
    cache_path = Path('.cache') / str(host) / str(port) / str(path).lstrip('/')

    # 2. Confirm the cache directory exists
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # Check the type of cache_data and encode if it's a string
    if isinstance(cache_data, str):
        cache_data = cache_data.encode("utf-8")

    # 3. Write the retrieved data to the file
    try:
        with open(cache_path, 'wb') as file:
            file.write(cache_data)
    except Exception as e:
        print(f"An error occurred while writing to cache: {str(e)}")


def connect_to_remote_server(host, path,port):
    """
    Connects to a specific server on a given port #, sends an HTTP GET request 
    for a resource, and retrieves the server's response. 
    
    Parameters:
    - host (str): The hostname or IP address of the server.
    - path (str): The path of the resource to request from the server.
    - port (int, optional): The port number on the server. Defaults to 80.
    
    Note:
    - The function uses HTTP/1.1 for the GET request and always requests the
      server to close the connection after the response.
    - Connection errors are gracefully handled and will not crash the program,
      though they will result in a lack of retrieved data.

    Returns:
    - bytes: The raw response from the server if successful. None otherwise.
    """

    try:
        # Create a socket object
        client_socket = socket(AF_INET, SOCK_STREAM)

        # Connect to the server
        client_socket.connect((host, port))

        # Prepare the request
        request = (f"GET {path} HTTP/1.1\r\n"
                   f"Host: {host}\r\nConnection: close\r\n\r\n")
        print('Sending the following message to the proxy server:\n', request)

        # Send the request & get response
        client_socket.send(request.encode())
        response = client_socket.recv(4096)

        # Receive the response
        return response

    except socket.error as e:
        print(f"Socket error: {str(e)}")

    finally:
        # Always close the socket
        client_socket.close()

def build_client_response(page_content, cache_hit, status_line):
    """
    Usage:
    Constructs a client HTTP response string by:
    1. Starting with the HTTP status line.
    2. Adding the Cache-Hit header.
    3. Appending the main content.

    Parameters:
    - page_content (str): The main content of the response.
    - cache_hit (bool): Indicates if the response data was fetched from cache.
    - status_line (str): The HTTP status line for the response.

    Returns:
    - str: A complete HTTP response to be sent to the client.
    """
     # 1. Build the Cache-Hit header
    cache_hit_header = f"Cache-Hit: {int(cache_hit)}"

    # 2. Combine the status line, Cache-Hit header, and response body
    longer_status_line = 'HTTP/1.1 ' + status_line
    client_response = (
    f"{longer_status_line}\r\n"
    f"{cache_hit_header}\r\n"
    "\r\n"
    f"{page_content.strip()}\r\n"
    "\r\n"
    )
    # 3. Return the client response
    return client_response

def split_response_data(returned_data):
    """
    Usage: 
    Splits the given response data into its headers and content sections.

    Parameters: 
    - returned_data (bytes): The raw HTTP response data to be split.

    Returns: 
    tuple: Two-element tuple containing:
        1. The headers (bytes) from the response.
        2. The main content (bytes) from the response.
        If the response doesn't contain headers and content as expected,
        both elements of the tuple will be empty bytes.
    """
    headers_and_content = returned_data.split(b'\r\n\r\n', 1)
    
    if len(headers_and_content) == 2:
        return headers_and_content
    else:
        # If the response doesn't contain headers and content as expected,
        # return empty bytes for both.
        return b"", b""

def get_status_code(headers):
    """
    Usage:
    Extract the status code from an HTTP response header.

    Parameters: 
    - headers (bytes): The HTTP response headers where the status code 
      will be extracted from.

    Returns:
    int: The status code extracted from the headers, or None if extraction 
         fails.
    """
    try:
        # Example of first line: "HTTP/1.1 200 OK"
        status_line = headers.split(b'\r\n')[0].decode()
        status_code = int(status_line.split()[1])
        return status_code
    except:
        return None

def get_content(returned_data):
    """
    Usage: 
    Extracts the content from the returned data, assuming it's in UTF-8 format.

    Parameters:
    - returned_data (bytes): The raw HTTP response which includes both headers 
      and content.

    Returns:
    str: The decoded content from the returned data. If decoding fails, an
         error will be raised.
    """

   # Split and return  
    _, content = split_response_data(returned_data)
    try:
        return content.decode()
    except UnicodeDecodeError:
        print("Warning: Unable to decode content using UTF-8. Returning raw bytes.")
        return content

main()