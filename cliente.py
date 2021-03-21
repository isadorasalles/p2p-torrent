import socket
import sys
import struct
import ipaddress
import os

def send_hello(s, qtd_chunks, ids, ip, port):
    msg_hello = struct.pack("H", 1)
    msg_hello += struct.pack("H", qtd_chunks)
    msg_hello += str.encode(ids)
    s.sendto(msg_hello, (ip, int(port)))

def send_get(s, intersect, addr):
    get = struct.pack("H", 4)
    get += struct.pack("H", len(intersect))
    get += str.encode(','.join(intersect))
    s.sendto(get, addr)

def save_file(fname, chunk):
    file_ = os.path.join("output/", fname)
    with open(file_, "wb") as out:
        out.write(chunk)

def main():
    ip_port = sys.argv[1]
    ip = ip_port.split(":")[0]
    port = ip_port.split(":")[1]
    ids = sys.argv[2]
    qtd_chunks = len(ids.split(","))

    # cria pasta para armazenar os pedaços do video
    os.makedirs("output/", exist_ok=True)

    # criando socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # mensagem tipo hello
    send_hello(s, qtd_chunks, ids, ip, port)

    ## variaveis para fazer controle dos chunks ja consultados e dos ja recebidos
    not_sent = ids.split(",")
    already_recv = []
    already_send = []
    save_peers_send = {}
    output = []

    # set timeout e retransmissoes
    s.settimeout(5)
    retrans_hello = 2
    retrans_get = 2

    while True:
        if len(not_sent) == 0 and len(already_recv) == len(already_send):
            break
        # aguarda recebimento de mensagens por um timeout de 5 segundos
        # caso nada seja recebido, a mensagem de HELLO eh retransmitida se nao tiver rebebido CHUNKS INFO para todos os ids desejados
        # e a mensagem de GET eh retransmitida se nao tiver recebido o RESPONSE correspondente
        try:
            msg_received, addr = s.recvfrom(1048)

        except socket.timeout:

            if retrans_hello == 0:
                print("Nao foi possivel encontrar os chunks: ", not_sent)
                for id_ in not_sent:
                    output.append("0.0.0.0:0 - "+str(id_)+"\n")
                not_sent = []

            if retrans_get == 0:
                already_send_not_recv = list(set(already_send)-(set(already_recv)))
                print("A resposta com os seguintes chunks nao foi recebida: ", already_send_not_recv)
                for id_ in already_send_not_recv:
                    output.append("0.0.0.0:0 - "+str(id_)+"\n")
                already_recv = already_send

            if len(not_sent) > 0 and retrans_hello > 0:
                # repetir mensagem de hello
                print("[Retransmitir mensagem HELLO] - nao recebemos os CHUNKS INFO para os ids:", str(not_sent))
                send_hello(s, len(not_sent), str(not_sent), ip, port)
                retrans_hello -= 1

            if len(save_peers_send) > 0 and retrans_get > 0:
                # repetir mensagens de get que ainda não foram recebidas
                print("[Retransmitir mensagem GET] - nao recebemos response para todos os CHUNKS requisitados")
                for k, v in save_peers_send.items():
                    send_get(s, v, k)
                retrans_get -= 1
            
            continue

        msg = struct.unpack("=HH"+str(len(msg_received)-4)+"s", msg_received)

        if msg[0] == 3:
            # recebeu mensagem do tipo chunks info
            print("CHUNKS_INFO recebido do peer", addr)
            chunks_with_peer = msg[2].decode().split(",") 

            # verifica se os ids recebidos tem intersecao com os desejados
            intersect = list(set(chunks_with_peer).intersection(not_sent))
            if not intersect:
                print("Nao teve nenhuma intersecao com os chunks restantes")
                continue

            # manda mensagem de get para os ids desejados que o peer possui
            send_get(s, intersect, addr)

            # atualiza estruturas que armazenam os ids enviados e não enviados
            not_sent = list(set(not_sent)-(set(intersect)))
            already_send.extend(intersect)
            save_peers_send[addr] = intersect

        if msg[0] == 5:
            # recebeu mensagem do tipo response
            print("RESPONSE recebido do peer", addr)

            # decodifica mensagem response corretamente
            msg = struct.unpack("=HHH"+str(len(msg_received)-6)+"s", msg_received)

            # salva o ID do chunk recebido e remove ID do dicionario de enviados
            already_recv.append(str(msg[1]))
            save_peers_send[addr].remove(str(msg[1]))
            if save_peers_send[addr] == []:
                del save_peers_send[addr]
        
            output.append(addr[0]+":"+str(addr[1])+" - "+str(msg[1])+"\n")
            save_file("BigBuckBunny_"+str(msg[1])+".m4s", msg[3])

    with open("output_"+s.getsockname()[0]+".log", "w") as out:
        for lines in output:
            out.write(lines)
    
if __name__ == "__main__":
    main()