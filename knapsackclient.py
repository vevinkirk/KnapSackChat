import base64
import socket
import select
import sys
import hashlib
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES




def encryption(message,publicKey):
    c = 0
    for i in range(len(publicKey)):
        #print message[i]
        #print publicKey[i]
        c += message[i] * publicKey[i]
    #print ("c is",c)
    return c

def mwInverse(u,v):
    u0 = u
    v0 = v
    t0 = 0
    t = 1
    s0 = 1
    s = 0
    q = v0/u0
    r = v0-q * u0
    while r > 0:
        temp = t0 - q * t
        t0 = t
        t = temp
        temp = s0 - q * s
        s0 = s
        s = temp
        v0 = u0
        u0 = r
        q = v0 / u0
        r = v0 - q * u0
    r = u0
    if r == 1:
        if t > 0:
            return t
        else:
            return t + v
    else:
        return 0

def decryption(message,privateKeyD):
    u = privateKeyD.W
    v = privateKeyD.M
    #print u
    #print v
    #print w
    #print message
    answer = [0]*n
    plaintext = [0]*n
    w = mwInverse(u,v)
    d = (w * message) % privateKeyD.M
    for i in reversed(range(n)):
        if d >= privateKeyD.superIncreasingSequence[i] :
            d -= privateKeyD.superIncreasingSequence[i]
            answer[i] = 1
        else:
            answer[i] = 0

    for j in range(n):
        plaintext[j] = answer[privateKeyD.permutation[j]-1]

    return plaintext


def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encryptAES(plaintext,key):
    '''obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    message = "The answer is no"
    ciphertext = obj.encrypt(message)
    return ciphertext'''
    plaintext = pad(plaintext)
    IV = Random.new().read(AES.block_size)
    cipher = AES.new(key,AES.MODE_CBC,IV)
    ciphertext = base64.b64encode(IV+cipher.encrypt(plaintext))
    return ciphertext

def decryptAES(ciphertext,key):
    '''obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    return obj2.decrypt(ciphertext)'''
    ciphertext = base64.b64decode(ciphertext)
    IV = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, IV)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext

def arrayToKey(arrayKey):
    string = ''
    for i in range(n):  #array to int
        string += str(arrayKey[i])
    key = hashlib.sha256(string).digest() # hash the string to get password
    return key

def main():
    global n
    n = 128
    global publicKey
    publicKey = []
    global RECVBUFFER
    RECVBUFFER = 2048
    global plainTextKey
    plainTextKey = []
    if len(sys.argv) != 3:
        print "USAGE: python file, IP, PORT"
        exit()

    IP = str(sys.argv[1])
    PORT = int(sys.argv[2])
    for i in range(n):
        plainTextKey.append(random.choice([0,1]))
    chatServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chatServer.connect((IP, PORT))
    sentPublicKey = chatServer.recv(12048)
    publicKey = sentPublicKey.split(",")
    publicKey = list(map(int,publicKey))
    cipherTextKey = encryption(plainTextKey,publicKey)
    sendCipherTextKey = str(cipherTextKey)
    chatServer.send(sendCipherTextKey)
    AESkey = arrayToKey(plainTextKey)
    #chatServer.connect((IP,PORT))
    #sockets_list = [sys.stdin,chatServer]
    #read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])

    while True:
        # maintains a list of possible input streams
        sockets_list = [sys.stdin, chatServer]
        read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])

        for socks in read_sockets:
            if socks == chatServer:
                messageServer = socks.recv(2048)
                if messageServer:
                    AESplainText = decryptAES(messageServer, AESkey)
                    print "Server Response:",
                    print AESplainText
                else:
                    print "Error"
                    exit()

            else:
                messageClient = sys.stdin.readline()
                if messageClient:
                    AEScipherText = encryptAES(messageClient,AESkey)
                    chatServer.send(AEScipherText)


    chatServer.close()

main()
