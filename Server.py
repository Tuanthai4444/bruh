import socket
import random
import string
import struct
import threading
import time

# Server bits
host_addr = "127.0.0.1"
port = 12235
buffer_size = 1024

# Hard-coded values
tsx_secret = 0
server_step = 2
persistent_time = 3
tcp_max = 20
sid = 996

header_size = 12
byte_align = 4
max_users = 20


def a_stage(udp_socket, addr, payload_len, psecret):
    print("Stage A")

    # Get our random values and append
    num = random.randint(5, 10)
    ln = random.randint(1, 100)
    udp_port = random.randint(1024, 65535)
    secreta = random.randint(1, 100)

    # Use python pack since it automatically formats in network order
    response_packet = struct.pack('!IIHHIIII', payload_len, psecret, server_step,
                                  sid, num, ln, udp_port, secreta)
    udp_socket.sendto(response_packet, addr)

    # Dict to hold response packet info (secret and port)
    new_packet = {"num": num, "ln": ln, "port": udp_port, "secret": secreta}
    print("Stage A finished")
    return new_packet


def b_stage(udp_port, ln, num, psecret, cli_addr):
    print("Stage B")
    new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    new_sock.bind((host_addr, udp_port))
    # Need timeout of 3
    new_sock.settimeout(3)

    count = 0
    while count < num:
        try:
            data_packet = new_sock.recv(buffer_size)
        except socket.timeout:
            new_sock.close()
            return None

        # 50% of non acknowledgement
        if random.randint(0, 1) == 0:
            continue

        # +4 bytes for the new pid (int)
        b_ln, b_psecret, b_step, b_sid, b_pid = \
            struct.unpack('!IIHHI', data_packet[:header_size+byte_align])

        # Do verifications, if we have num = 6 then we want max ACK 5
        if b_ln != ln+byte_align or b_pid != count or b_psecret != psecret:
            return None

        # ACK packet
        ack = struct.pack('!IIHHI', b_ln, b_psecret, server_step, b_sid, b_pid)

        new_sock.sendto(ack, cli_addr)
        count += 1

    # Create new secret b and tcp port for part c
    tcp_port = random.randint(1024, 65535)
    secretb = random.randint(1, 100)
    new_packet = struct.pack('!IIHHII', ln, psecret,
                             server_step, sid, tcp_port, secretb)
    new_sock.sendto(new_packet, cli_addr)
    new_sock.close()

    new_packet = {"num": num, "ln": ln, "port": tcp_port, "secret": secretb}
    print("Stage B finished")
    return new_packet


def cd_stage(tcp_port, bsecret):
    print("Stage C")
    # Create new tcp socket
    new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_sock.bind((host_addr, tcp_port))
    new_sock.listen(tcp_max)

    while True:
        try:
            # We only want to progress once tcp accept is fulfilled
            conn, cli_addr = new_sock.accept()
            num2 = random.randint(5, 10)
            ln2 = random.randint(1, 100)
            csecret = random.randint(1, 100)
            # We want a random char converted to utf-8
            c = random.choice(string.ascii_letters)
            c_byte = bytes(c, 'utf-8')

            # Pack provides x which is a single byte non typed filler
            # We fill to make it 4 byte aligned
            response_packet = struct.pack('!IIHHIIIcxxx', ln2, bsecret,
                                          server_step, sid, num2, ln2, csecret, c_byte)
            conn.sendto(response_packet, cli_addr)
            print("Stage C finished")

            print("Stage D")

            # We want to make sure we are 4-byte aligned here so that we are
            # taking in the right amount of bytes from num2
            count = 0
            buffer = header_size+ln2
            if buffer % byte_align != 0:
                buffer = (buffer + (byte_align - (buffer % byte_align)))

            # Same as in part b with no time constraint
            while count < num2:
                data_packet = conn.recv(buffer)

                # Unpack header for info
                r_ln, rsecret, rstep, rsid = struct.unpack('!IIHH', data_packet[0:header_size])
                payload = data_packet[header_size:header_size + ln2]
                # Secret check like before
                if csecret != rsecret:
                    print("fail")
                    continue

                # Check that payload is filled with char c but only check
                # r_ln num bytes to not read extraneous bytes
                i = 0
                while i < r_ln:
                    if chr(payload[i]) != c:
                        return None
                    i += 1

                count += 1
            break
        except:
            new_sock.close()

    dsecret = random.randint(1, 100)
    dresponse_packet = struct.pack('!IIHHI', ln2, csecret, server_step, sid, dsecret)
    conn.sendto(dresponse_packet, cli_addr)
    conn.close()
    new_sock.close()
    print("Stage D Finished")
    return 1


def run(udp_socket, payload_len, psecret, cli_addr):
    if psecret == tsx_secret:
        a_info = a_stage(udp_socket, cli_addr, payload_len, psecret)
        if a_info is None:
            print("Failed Stage A")
            return
        b_info = b_stage(a_info['port'], a_info['ln'],
                         a_info['num'], a_info['secret'], cli_addr)
        if b_info is None:
            print("Failed Stage B")
            return
        c_info = cd_stage(b_info['port'], b_info['secret'])
        if c_info is None:
            print("Failed Stage C")
            return
    else:
        print("Failed Stage A")
        return


def main():
    # UDP socket creation
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((host_addr, port))

    mthreads = []
    try:
        while True:
            # We want to only start the thread if we receive anything
            data_addr_pair = udp_sock.recvfrom(buffer_size)
            # We don't want to check these two fields to prevent DDOS attack
            data = data_addr_pair[0]
            cli_addr = data_addr_pair[1]

            # Check if empty
            if not data:
                udp_sock.close()
                return

            # We need to encode hello world with terminator
            tsx_keyword = 'hello world' + '\0'
            tsx_payload = tsx_keyword.encode('utf-8')

            # Check if we have the hello world payload to start tsx
            payload_len, psecret, step, inc_sid = struct.unpack('!IIHH', data[:header_size])
            # We want to use 12+payload_len to prevent extraneous bytes
            payload = data[header_size:header_size + payload_len]

            if payload == tsx_payload:
                # Basic thread management
                print(f"{threading.active_count()}")
                while threading.active_count() >= max_users:
                    time.sleep(5)

                t = threading.Thread(target=run(udp_sock, payload_len, psecret, cli_addr))
                t.start()
                mthreads.append(t)
            else:
                udp_sock.close()
                return

    except KeyboardInterrupt:
        print("Ctrl+C by host")
    finally:
        for t in mthreads:
            t.join()
        udp_sock.close()


if __name__ == '__main__':
    main()
