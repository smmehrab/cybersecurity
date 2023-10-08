import socket
import re

def min_changes_to_palindrome(s):
    changes = 0
    i = 0
    j = len(s) - 1
    while i < j:
        if s[i] != s[j]:
            changes += 1
        i += 1
        j -= 1
    return changes

# print(min_changes_to_palindrome('vKVoSVmkjKfVPkkOYSsogzNFqxfAXYnrQdDbthyDHXPbVSNPCNqyyzgSYPcgXJsmnrffbJhEKtCrDCWETijATIWowIzvrrofWaxpscwfsEfuwtPcsPTBzOIGYdccvwCBcndwhjfxPmoUS'))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('45.76.177.238', 5000)
sock.connect(server_address)

try:
    for _ in range(1000):
        data = sock.recv(1024)
        print('received {!r}'.format(data))
        match = re.search(r'String for query \d+ / 1000 : (.*)', data.decode())
        if match:
            s = match.group(1)
            changes = min_changes_to_palindrome(s)
            print('sending {!r}'.format(changes))
            sock.sendall((str(changes) + '\n').encode())

    # Continue receiving data after the loop
    while True:
        data = sock.recv(4096)
        if not data:
            break
        print('received {!r}'.format(data))

finally:
    print('closing socket')
    sock.close()
