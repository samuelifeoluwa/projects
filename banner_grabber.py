import socket

target = input('Enter Ipaddress: ')
port = int(input('Enter port to connect on: '))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target,port))

response = s.recv(1024)
print(response.decode())
s.close()