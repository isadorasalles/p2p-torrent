import socket
import sys
import struct
import ipaddress
import time

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

def main():
    ip_port = sys.argv[1]
    ip = ip_port.split(":")[0]
    port = ip_port.split(":")[1]
    ids = sys.argv[2]
    qtd_chunks = len(ids.split(","))

    # criando socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(s.getsockname())

    # mensagem tipo hello
    send_hello(s, qtd_chunks, ids, ip, port)

    ## variaveis para fazer controle dos chunks ja consultados e dos ja recebidos
    not_sent = ids.split(",")
    already_recv = []
    already_send = []
    save_peers_send = {}
    output = []

    # timeout e retransmissoes
    s.settimeout(5)
    retrans_hello = 2
    retrans_get = 2
    print(s.getsockname())
    while True:
        print(already_recv)
        print(already_send)
        print(save_peers_send)
        print(not_sent)
        if len(not_sent) == 0 and len(already_recv) == len(already_send):
            break
        # aguarda mensagens
        # implementar temporizador para recebimento de todos os chunks
        try:
            msg_received, addr = s.recvfrom(1048)

        except socket.timeout:

            if retrans_hello == 0:
                print("final: not sent", not_sent)
                for id_ in not_sent:
                    output.append("0.0.0.0:0 - "+str(id_))
                not_sent = []

            if retrans_get == 0:
                # already_recv = map(str, already_recv)
                already_send_not_recv = list(set(already_send)-(set(already_recv)))
                print("final: already send not recv", already_send_not_recv)
                for id_ in already_send_not_recv:
                    output.append("0.0.0.0:0 - "+str(id_))
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
            print("Chunks info recebido do peer", addr)
            chunks_with_peer = msg[2].decode().split(",") 
            intersect = list(set(chunks_with_peer).intersection(not_sent))
            if not intersect:
                print("Nao teve nenhuma intersecao com os chunks restantes")
                continue
            send_get(s, intersect, addr)
            # depois de um certo tempo se a lista de chunks nao enviados ainda nao estiver vazia pode ser que mensagens tenham
            # sido perdidas (ou entao alcançou o ttl), dessa forma eh possivel retransmitir a mensagem do tipo hello e começar uma nova busca na rede
            # salvar intersect e addr num dict, quando receber a resposta tira do dict,
            # depois de um dado timeout sem receber nenhuma resposta, retransmite tudo que ta no dict
            not_sent = list(set(not_sent)-(set(intersect)))
            already_send.extend(intersect)
            save_peers_send[addr] = intersect

        if msg[0] == 5:
            # recebeu mensagem do tipo response
            print("Response recebida do peer", addr)

            # decodifica mensagem response corretamente
            msg = struct.unpack("=HHH"+str(len(msg_received)-6)+"s", msg_received)

            # salva o ID do chunk recebido e remove ID do dicionario de enviados
            already_recv.append(str(msg[1]))
            save_peers_send[addr].remove(str(msg[1]))
            if save_peers_send[addr] == []:
                del save_peers_send[addr]
        
            output.append(addr[0]+":"+str(addr[1])+" - "+str(msg[1])) ## falta escrever em um arquivo

        # falta criar as pastas do cliente e salvar os pedaços dos chunks nelas

    print(output)
if __name__ == "__main__":
    main()