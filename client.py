import socket
import select
import sys

def get_type():
    """Asks the user to enter which type of information they want to recieve from the server (date / time). Returns the hex value that corresponds to the info the user provides."""
    dt = input("Please enter either 'date' or 'time': ").lower()
    if dt == 'date':
        return 0x0001
    elif dt == 'time':
        return 0x0002
    else:
        print('Error: Invalid input.')
        sys.exit()

def get_addr():
    """Asks the user to enter the IP address / host-name they wish to send a DT-Request packet to. Returns the addr in dotted decimal notation of the IP / Host."""
    ip = input('Please enter either your IP address or \nhost-name of server: ')
    try:
        addr = socket.gethostbyname(ip)
        return addr
    except:
        print('Error: Badly formed IP address or hostname!')
        sys.exit()

def get_port():
    """Asks the user to enter the port number they wish to send a DT-Request packet to. Returns the port to be further processed."""
    port = input('Please enter three port number \nbetween [1024, 64000]: ')
    if 1024 <= int(port) <= 64000:
        return int(port)
    else:
        print('Error: Invalid port')
        sys.exit()

def check_response(p):
    """Takes the DT-Response packet recieved from the server as input, and performs all nessasary checks to make sure what was recieved is a valid packet."""
    text = p[13:]
    
    if len(p) < 13:
        print('Error: Packet does not contain a full header.')
        sys.exit()
    elif (p[0] << 8) + p[1] != 0x497e:
        print('Error: Invalid Magic Number.')
        sys.exit()
    elif (p[2] << 8) + p[3] != 0x0002:
        print('Error: Invalid Packet Type.')
        sys.exit()
    elif (p[4] << 8) + p[5] not in [0x0001, 0x0002, 0x0003]:
        print('Error: Invalid Language Code.')
        sys.exit()
    elif (p[6] << 8) + p[7] >= 2100:
        print('Error: Invalid Year.')
        sys.exit()
    elif p[8] not in range(1, 12):
        print('Error: Invalid Month.')
        sys.exit()
    elif p[9] not in range(1, 31):
        print('Error: Invalid Day.')
        sys.exit()
    elif p[10] not in range(0, 23):
        print('Error: Invalid Hour.')
        sys.exit()
    elif p[11] not in range(0, 59):
        print('Error: Invalid Minute.')
        sys.exit()
    elif p[12] != 13 + len(text):
        print('Error: Invalid Packet Length.')
        sys.exit()

        
def print_packet(p):
    """Takes the DT-Response packet recieved from the server as input, and prints a string containing all information recieved within that packet."""
    # Small check to change the time to 12 hour format.
    ampm = 'am'
    if p[10] >= 12:
        ampm = 'pm'
        
    # Formated string with all information contained within the packet.
    string = f"""
    -------------------------
    Date Time Response Packet
    -------------------------
    Magic Number:  {hex((p[0] << 8) + p[1])}
    Packet Type:   {hex((p[2] << 8) + p[3])}
    Language Code: {hex((p[4] << 8) + p[5])}
    Packet Length: {p[9]}
    (DD/MM/YYYY):  {p[9]}/{p[8]}/{(p[6] << 8) + p[7]}
    (hh:mm):       {p[10]%12}:{p[11]}{ampm}
    Date / Time:   {p[13:].decode('utf-8')}
    -------------------------"""
    print(string)
    sys.exit()
    

def main():
    """Main client control function."""
    # Definition / calls to functions required for a DT-Request header.
    magicNo = 0x497e
    packetType = 0x0001    
    requestType = get_type()
    addr = get_addr()
    port = get_port()
    
    # Creation of DT-Request packet.
    dtRequest = bytearray(magicNo.to_bytes(2, 'big') + packetType.to_bytes(2, 'big') + requestType.to_bytes(2, 'big'))
    
    # Sending / Recieving client socket.
    sockClient = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockClient.sendto(dtRequest, (addr, port))
    # Loop that waits for a response into the sockClient.
    readable, writable, exceptional = select.select([sockClient], [], [sockClient], 1.0)
    
    # Making sure the server responds within 1 sec.
    if not readable:
        print("Error: Server took to long to respond. (>1s)")
        sys.exit()
        
    # Gets the information sent to sockClient    
    for s in readable:
        if s is sockClient:
            data, addr = sockClient.recvfrom(port)
            check_response(data)
            print_packet(data)
            
                
# Call to main client function.
if __name__ == '__main__':
    main()