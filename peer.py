import socket
import threading
import sys
import struct
import os
import ipaddress

def send_chunks_info(s, ids, addr, chunks_asked):
    # mandar informacoes dos chunks que o peer possui e o cliente deseja
    chunks_asked = chunks_asked.decode().split(",") 
    ids_send = list(set(chunks_asked).intersection(ids))
    if len(ids_send) > 0:
        chunks_info = struct.pack("H", 3)
        chunks_info += struct.pack("H", len(ids_send))
        chunks_info += str.encode(','.join(ids_send))
        s.sendto(chunks_info, addr)

def send_flooding_msg(s, p, ttl, qtd_chunks, list_ids, neighbors, addr):
    for peer in neighbors:
        peer_ip = peer.split(":")[0]
        peer_port = peer.split(":")[1]

        if (peer_ip, int(peer_port)) == p:  # verifica se o peer eh igual ao que mandou a mensagem de alagamento
            continue

        # transforma ip para 4 bytes
        address = ipaddress.IPv4Address(addr[0])  
        address_as_int = int(address)
        adress_as_bytes = address_as_int.to_bytes(4, byteorder='big')

        query = struct.pack("H", 2)
        query += adress_as_bytes
        query += struct.pack("H", addr[1])
        query += struct.pack("H", ttl)
        query += struct.pack("H", qtd_chunks)
        query += list_ids

        # manda mensagem para outros peers vizinhos
        s.sendto(query, (peer_ip, int(peer_port)))

def main():
    ip_port = sys.argv[1]
    ip = ip_port.split(":")[0]
    port = ip_port.split(":")[1]
    key_values_files = sys.argv[2]
    neighbors = sys.argv[3:]
    
    # pre-processamento da lista de chunks que o peer tem disponivel
    with open(key_values_files, "r") as f:
        keys = f.readlines()
    chunks = {k.split(":")[0]: k.split(":")[1].replace(" ", "").replace("\n", "") for k in keys}
    ids = [k.split(":")[0] for k in keys]

    # cria pasta para armazenar os arquivos
    os.makedirs("output/", exist_ok=True)

    # cria socket ipv4
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, int(port)))

    while(1):
        msg_received, addr = s.recvfrom(1024)
        length_chunks = len(msg_received) - 4 # 2 bytes de tipo da mensagem + 2 bytes de quantidade de chunks
        msg = struct.unpack("=HH"+str(length_chunks)+"s", msg_received)
        
        if msg[0] == 1:
            # recebeu mensagem do tipo hello
            print("HELLO recebida de {}".format(addr))
           
            # manda mensagem de alagamento
            send_flooding_msg(s, 0, 3, msg[1], msg[2], neighbors, addr)
            
            # manda chunks info para o cliente
            send_chunks_info(s, ids, addr, msg[2])

        if msg[0] == 2:
            # recebeu mensagem de alagamento
            print("QUERY recebida de {}".format(addr))

            # decodifica mensagem de alagamento corretamente
            length_chunks = len(msg_received) - 12
            alagamento = struct.unpack("=H4sHHH"+str(length_chunks)+"s", msg_received)
            
            # transforma ip do cliente de bytes para o fomato ip
            ip_client = ipaddress.ip_address(alagamento[1])
            port_client = alagamento[2]

            # manda mensagem de alagamento para seus vizinhos, se o TTL for maior que 0
            if len(neighbors) > 0 and alagamento[3] - 1 > 0:
                send_flooding_msg(s, addr, alagamento[3] - 1, alagamento[4], alagamento[5], neighbors, (str(ip_client), port_client))
            
            # manda chunks info para o cliente
            send_chunks_info(s, ids, (str(ip_client), port_client), alagamento[5])

        if msg[0] == 4:
            # recebeu mensagem do tipo get
            chunks_asked = msg[2].decode().split(",") 
            print("Chunks pedidos pelo cliente: {}".format(chunks_asked))

            # manda apenas os chunks requisitados pelo cliente
            for i in chunks_asked:
                with open(chunks[i], "rb") as f:
                    data = f.read()
                response = struct.pack("H", 5)
                response += struct.pack("H", int(i))
                response += struct.pack("H", len(data))
                response += data
                s.sendto(response, addr)
                   
if __name__ == "__main__":
    main()