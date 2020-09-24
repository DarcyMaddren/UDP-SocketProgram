import socket
import select
import time
import sys

def get_ports():
    """Asks the user to enter the three ports that will correspond to English, Maori or German language responses."""
    ports = input('Please enter three port numbers in range [1024, 64000] \nin the form "engPort mriPort gerPort": ')
    ports = ports.split(' ')
    if len(ports) == 3:
        return int(ports[0]), int(ports[1]), int(ports[2])
    else:
        print('Error: Invalid port inputs.')
        sys.exit()


def check_ports(p1, p2, p3):
    """Takes three port numbers as inputs and performs validity checks on each of them."""
    if p1 == p2 or p1 == p3 or p2 == p3:
        print('Error: Identical Ports.')
        sys.exit()
    elif 1024 > p1 > 64000 or 1024 > p2 > 64000 or 1024 > p3 > 64000:
        print('Error: Invalid Ports. Valid Range: [1024 - 64000]')
        sys.exit()


def bind_ports(p1, p2, p3, s1, s2, s3):
    """Takes three port numbers and three sockets as inputs and binds the corresponding ports to each given socket."""
    try:
        s1.bind(('localhost', p1))
        s2.bind(('localhost', p2))
        s3.bind(('localhost', p3))
        print('Server: Sucessfully bound ports.')
    except:
        print('Error: Failed to bind ports.')
        sys.exit()
        
        
def check_request(packet):
    """Takes a DT-Request packet as an input and performs the required checks to ensure the packet / request has been sent correctly."""
    if len(packet) != 6:
        print('Error: Packet length not valid.\nServer: Packet discarded.')
    elif ((packet[0] << 8) + packet[1]) != 0x497e:
        print('Error: Invalid Magic Number.\nServer: Packet discarded.')
    elif ((packet[2] << 8) + packet[3]) != 0x0001:
        print('Error: Invalid Packet Type.\nServer: Packet discarded.')
    elif ((packet[4] << 8) + packet[5]) not in [0x0001, 0x0002]:
        print('Error: Invalid Request Type.\nServer: Packet discarded.')


def prep_textual(lang, reqType, year, month, day, hour, minute):
    """Takes the client requested language, request type, and current date information as inputs. Baised on the request type and language will return a string representing the date or time."""
    dictEng = {1: "January", 2: "February", 3: "March", 4: "April", 5: "May", 6: "June", 7: "July", 8: "August", 9: \
               "September", 10: "October", 11: "November", 12: "December"}
    dictMri = {1: "Kohitatea", 2: "Hui-tanguru", 3: "Poutu-te-rangi", 4: "Paenga-whawha", 5: "Haratua", 6: "Pipiri", \
               7: "Hongongoi", 8: "Here-turi-koka", 9: "Mahuru", 10: "Whiringa-a-nuku", 11: "Whiringa-a-rangi", 12: "Hakihea"} 
    dictGer = {1: "Januar", 2: "Februar", 3: "Marz", 4: "April", 5: "Mai", 6: "Juni", 7: "Juli", 8: "August", 9: "September", \
               10: "Oktober", 11: "November", 12: "Dezember"}
    
    if reqType == 0x0001:
        if lang == 0x0001:
            return f"Today's date is {dictEng[month]} {day}, {year}"
        elif lang == 0x0002:
            return f"Ko te ra o tenei ra ko {dictMri[month]} {day}, {year}"
        else:
            return f"Heute ist der {day}. {dictGer[month]} {year}"
    else:
        if lang == 0x0001:
            return f"The current time is {hour}:{minute}"
        elif lang == 0x0002:
            return f"Ko te wa o tenei wa {hour}:{minute}"
        else:
            return f"Die Uhrzeit ist {hour}:{minute}"        
    
  
def prep_response(langCode, text, year, month, day, hour, minute):
    """Takes the client request language, text returned by prep_textual() and the current date information as inputs. Returns a DT-Response packet that is to be sent to the client."""
    magicNo = 0x497e
    packetType = 0x0002
    textBytes = text.encode('utf-8')
    textLength = len(textBytes)
    
    if textLength > 255:
        print('Error: Invalid Text Field.')
        return None
         
    dtResponse = bytearray(magicNo.to_bytes(2, 'big') \
                           + packetType.to_bytes(2, 'big') \
                           + langCode.to_bytes(2, 'big') \
                           + year.to_bytes(2, 'big') \
                           + month.to_bytes(1, 'big') \
                           + day.to_bytes(1, 'big') \
                           + hour.to_bytes(1, 'big') \
                           + minute.to_bytes(1, 'big') \
                           + (13 + textLength).to_bytes(1, 'big') \
                           + textBytes)
    return dtResponse


def main():
    """Main server control function, basicaly runs the UDP server."""   
    # Getting and checking validity of ports.
    portEng, portMri, portGer = get_ports()
    check_ports(portEng, portMri, portGer)
    
    # Creating and binding sockets to ports.
    sockEng = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockMri = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockGer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_ports(portEng, portMri, portGer, sockEng, sockMri, sockGer)
    
    # Definition of sockets that need to be listened to.
    sockets = [sockEng, sockMri, sockGer]
    
    # Loop that is always true so the server is continuously running, for clients to make requests.
    while True:
        # Loop that listens for a request into one of the sockets
        readable, writable, exceptional = select.select(sockets, [], sockets)
        
        # Loop that checks if any of the sockets recieved data.
        for s in readable:
            if s is sockEng:
                data, addr = sockEng.recvfrom(portEng)
                langCode = 0x0001
                sock, port = sockEng, portEng
                break
            if s is sockMri:
                data, addr = sockMri.recvfrom(portMri)
                langCode = 0x0002
                sock, port = sockMri, portMri
                break
            if s is sockGer:
                data, addr = sockGer.recvfrom(portGer)
                langCode = 0x0003
                sock, port = sockGer, portGer
                break
            
        # Checks any data recieved through a socket.
        check_request(data)
        
        # Creation of the current date / time information,
        curTime = time.localtime()
        year, month, day, hour, minute = curTime.tm_year, curTime.tm_mon, curTime.tm_mday, curTime.tm_hour, curTime.tm_min
        
        # Creates the DT-Response packet, with the text in the given language.
        text = prep_textual(langCode, (data[4] << 8) + data[5], year, month, day, hour, minute)
        dtResponse = prep_response(langCode, text, year, month, day, hour, minute)
        
        # Sends the DT-Response back to the client
        if dtResponse is not None:
            sock.sendto(dtResponse, addr)
            print(f'Server: Sent DT-Response packet to {addr[0]} on port {port}.')
            sockEng.close()
            sockMri.close()
            sockGer.close()
            sys.exit()

# Call to main server function.
if __name__ == '__main__':
    main()
