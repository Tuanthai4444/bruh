import time
import socket
import math
import time


def intToBit(size, message):
    return message.to_bytes(size, 'big')
def extractInt(message):
    return int.from_bytes(message, "big")

def extractString(b):
    return b.decode('ascii')

def generateHeader(message, psecret, step):
    # -------- header --------
    payload_len = intToBit(4, len(message))
    ps = intToBit(4, psecret)
    st = intToBit(2, step)
    digits_student_id = intToBit(2, 430)
    header = payload_len + ps + st + digits_student_id
    
    return header

def send(sock, message, server, port):
    sock.sendto(message, (server, port))

def extractHeader(data):
    bc=0
    payload_len = extractInt(data[bc:bc+4])
    bc+=4
    psecret = extractInt(data[bc:bc+4])
    bc+=4
    step = extractInt(data[bc:bc+2])
    bc+=2
    studentId = extractInt(data[bc:bc+2])
    bc+=2
    return (data[bc:], payload_len, psecret, step, studentId)

done=False
while not done:
    print("\n----- Start Programm -----")
    try:

        #SERVER_DNS = "attu2.cs.washington.edu"
        SERVER_DNS = "attu4.cs.washington.edu"
        UDP_PORT = 12235
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock: # Internet, UDP

            MESSAGE = b'hello world\x00'
            header = generateHeader(MESSAGE, 0, 1)

            total = header + MESSAGE
            send(sock, total, SERVER_DNS, UDP_PORT)

            # -------- part 1 -------- 
            # --- step a1 
            print("--- phase a1 ---")
            data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
            #print("received message: %s" % data)

            (payload, payload_len, psecret, step, studentId) = extractHeader(data)

            # --- step a2
            print("--- phase a2 ---")
            bc=0
            a2num = extractInt(payload[bc:bc+4])
            bc+=4
            a2len = extractInt(payload[bc:bc+4])
            bc+=4
            a2udp_port = extractInt(payload[bc:bc+4])
            bc+=4
            a2secretA = extractInt(payload[bc:bc+4])
            bc+=4

            print ("--- header:")
            print("payload_len:" + str(payload_len))
            print("psecret:" + str(psecret))
            print("step:" + str(step))
            print("studentId:" + str(studentId))
            print ("--- payload:")
            print("num:" + str(a2num))
            print("len:" + str(a2len))
            print("a2udp_port:" + str(a2udp_port))
            print("a2secretA:" + str(a2secretA))

            print("-"*20 + "\n")
            sock.close()



            # --- phase b1 --- 
            print("--- phase b1 ---")

            buffer = {}
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)

                for packetId in range(0, a2num):
                    correctedlength = int(math.ceil(float(a2len) / 4.0)*4.0)
                    #print(correctedlength)
                    packetPayload = b'\x00'*correctedlength
                    #print(packetPayload)
                    #print(packetId)
                    packet = intToBit(4,packetId) + packetPayload
                    
                    header = generateHeader(packet, a2secretA, 1)
                    total = header+packet
                    buffer[packetId] = total
                    
                    send(sock, total, SERVER_DNS, a2udp_port)

                    unackedCounter = 0
                    
                    # receive ack
                    unacked = True
                    while unacked:
                        try:
                            data, addr = sock.recvfrom(1024)
                            (data, payload_len, psecret, step, studentId) = extractHeader(data)
                            ack = extractInt(data[0:4])
                            print("ack received:" + str(ack))
                            unacked = False
                        except socket.timeout:
                            print("packet timeout for id: " + str(packetId))
                            send(sock, total, SERVER_DNS, a2udp_port)
                            unackedCounter +=1
                        if (unackedCounter == 9):
                            raise Exception("server does not respond")
                    
                data, addr = sock.recvfrom(1024)                
                (data, payload_len, psecret, step, studentId) = extractHeader(data)
                tcp_port = extractInt(data[0:4])
                secretB = extractInt(data[4:8])
                print("tcp_port: " + str(tcp_port))
                print("secretB: " + str(secretB))
                sock.close()

                print("-"*20 + "\n")



                # --- phase c1 --- 
                print("--- phase c1 ---")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((SERVER_DNS, tcp_port))
                    
                    print("--- phase c2 ---")
                    data = s.recv(1024)
                    (data, payload_len, psecret, step, studentId) = extractHeader(data)
                    print(data)
                    num2 = extractInt(data[0:4])
                    len2 = extractInt(data[4:8])
                    secretC = extractInt(data[8:12])
                    character = data[12]
                    print(data[12])
                    
                    print("num2: " + str(num2))
                    print("len2: " + str(len2))
                    print("secretC: " + str(secretC))
                    print("character: >" + str(character) + "<")
                    #s.close()

                    #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                    buffer = {}
                    print("--- phase d1 ---")
                    s.settimeout(1)
                    correctedlength = int(math.ceil(float(len2) / 4.0)*4.0)
                    print("correctedlength: " + str(correctedlength))
                    for packetId in range(0, num2):
                        packetPayload = intToBit(1,character)*correctedlength
                        #packetPayload = intToBit(1,character)*len2 + (correctedlength - len2) * b'\x00'
                        #print(packetPayload)
                        print("send packet " + str(packetId))
                        packet = packetPayload
                            
                        header = generateHeader(packet, secretC, 1)
                        total = header+packet
                        buffer[packetId] = total
                            
                        s.sendall(total)
                        time.sleep(0.3)
                        #data = s.recvfrom(1024)
                        #print(data)
                            
                    print("--- phase d2 ---")           
                    data = s.recv(1024)
                    print(data)
                    (data, payload_len, psecret, step, studentId) = extractHeader(data)
                    secretD = extractInt(data[0:4])
                    print("secretD: " + str(secretD))
            

        print("-"*20 + "\n")
        done=True
    except Exception as e:
        print(e)
        print("\n----- Trigger Restart -----")
input("Press Enter to continue...")
