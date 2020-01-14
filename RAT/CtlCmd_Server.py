import socket
import time

TCP_IP = '172.30.159.1'
TCP_PORT = 8888
ADDR = (TCP_IP, TCP_PORT)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(ADDR)
sock.listen(10)

while True :
    data, addr = sock.accept()
    if not data :
    	break
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), end='	')
    print('CLIENT ADDRESS : ', repr(addr))
    print(repr(data.recv(1450).decode("utf-8")))
    cmd = input()
    data.send(cmd.encode())
    data.close()
    if(cmd == 'exit') :
        break

sock.shutdown(2)
sock.close()
