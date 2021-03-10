import socket
import sys
import struct
import ipaddress


def main():
    ip_port = sys.argv[1]
    ip = ip_port.split(":")[0]
    port = ip_port.split(":")[1]
    ids = sys.argv[2]
    qtd_chunks = len(ids.split(","))

    # criando socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # mensagem tipo hello
    msg_hello = struct.pack("H", 1)
    msg_hello += struct.pack("H", qtd_chunks)
    msg_hello += str.encode(ids)
    s.sendto(msg_hello, (ip, int(port)))

    ## fazer controle dos chunks ja consultados e dos ja recebidos
    not_sent = ids.split(",")
    already_recv = []
    already_send = []
    output = []

    while True:
        if len(not_sent) == 0 and len(already_recv) == len(already_send):
            break
        # aguarda mensagens
        msg, addr = s.recvfrom(1048)
        print(already_recv)
        print(already_send)
        if len(msg) <= 24:  ## verificar isso
            msg = struct.unpack("=HH"+str(len(msg)-4)+"s", msg)
            if msg[0] == 3:
                # tipo chunks_info
                print("recebi um chunks info:")
                print(addr)
                chunks_with_peer = msg[2].decode().split(",") 
                intersect = list(set(chunks_with_peer).intersection(not_sent))
                if not intersect:
                    print("Nao teve nenhuma intersecao com os chunks que quero")
                    print(addr)
                    continue
                get = struct.pack("H", 4)
                get += struct.pack("H", len(intersect))
                get += str.encode(','.join(intersect))
                s.sendto(get, addr)
                not_sent = list(set(not_sent)-(set(intersect)))
                print(not_sent)
                already_send.extend(intersect)
        else:
            msg = struct.unpack("=HHH"+str(len(msg)-6)+"s", msg)
            already_recv.append(msg[1])
            output.append(addr[0]+":"+str(addr[1])+" - "+str(msg[1]))

    print(output)
if __name__ == "__main__":
    main()