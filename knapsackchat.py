import socket
import select
import sys
import random
import string
from thread import *
import fractions
import pdb
import base64
import time
import os
import itertools
import hashlib
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES


class privateKeyClass:
    permutation = []
    M = 0
    W = 0
    superIncreasingSequence = []
    def __str__(self):
        string = "(("
        string += ','.join(str(n) for n in self.permutation)
        string += ")," + str(self.M)
        string += "," + str(self.W)
        string += ",("
        string += ','.join(str(e) for e in self.superIncreasingSequence)
        string += "))"
        return string

def generate_private_key(n):
    lowerBound = 0
    superIncreasingSequence = []

    for counter in range(0,n):
        upperBound = lowerBound * 2 + 100
        temp = random.randint(lowerBound,upperBound)
        superIncreasingSequence.append(temp)
        lowerBound += temp

    #print superIncreasingSequence

    M = random.randint(lowerBound,(lowerBound*2))
    #print M
    reset = 1
    for i in range(1,M+1):          #creat W
        W = random.randint(1, M+1)
        if fractions.gcd(M,W) == 1 :  #test W
            reset = 0
            break;
    #print W
    privateKey.M = M
    privateKey.W= W

    for j in superIncreasingSequence:
        #print j
        privateKey.superIncreasingSequence.append(j);


    for i in range(n): # genrate sequence permutation
        privateKey.permutation.append(i)
    random.shuffle(privateKey.permutation)


    #print privateKey

    return privateKey

def generate_public_key(n):
    publicKey = [0]*n
    #print privateKey.M
    for j in range(n): #genrate public key
        publicKey[j] = (privateKey.W * privateKey.superIncreasingSequence[privateKey.permutation[j]-1]) % privateKey.M
    return publicKey

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

def keyGenerate(n):
    global privateKey
    privateKey = privateKeyClass()
    global publicKey
    publicKey = []
    reset = 1
    reset2 = 1
    reset3 = 1
    while reset or reset2 or reset3:
        lowerBound = 0
        for i in range(n):
            temp = random.randint(lowerBound,(lowerBound*2)+100)
            #print privateKey.superIncreasingSequence[i]
            privateKey.superIncreasingSequence.append(temp)
            lowerBound += temp

        privateKey.M = random.randint(lowerBound,(lowerBound*3))

        hold = 0
        reset = 0
        for i in range(n):
            if privateKey.superIncreasingSequence[i] < hold:
                reset = 1
            else:
                hold += privateKey.superIncreasingSequence[i]

        reset2 = 1
        for _ in itertools.count(1):
            privateKey.W = random.randint(1, privateKey.M+1)
            if fractions.gcd(privateKey.M,privateKey.W) == 1:
                reset2 = 0
                break;
        reset3 = 1
        if(1<privateKey.W) and (privateKey.W < (privateKey.M+1)):
            reset3 = 0

        for i in range(n):
            privateKey.permutation.append(i)

        random.shuffle(privateKey.permutation)

        for i in range(n):
            publicKey.append((privateKey.W * privateKey.superIncreasingSequence[privateKey.permutation[i]-1])%privateKey.M)



def generate_word(length):
    VOWELS = "aeiou"
    CONSONANTS = "".join(set(string.ascii_lowercase) - set(VOWELS))
    word = ""
    for i in range(length):
        if i % 2 == 0:
            word += random.choice(CONSONANTS)
        else:
            word += random.choice(VOWELS)
    return word



def clientThread(connection, address,AESkey):

    #connection.send("Welcome to the Nebula Cyber Chatroom! THE MODS ARE ALWAYS WATCHING")

    while True:
        try:
            message = connection.recv(2048)
            if message:
                AESplainText = decryptAES(message, AESkey)
                print address[0] + " " +AESplainText
                message_to_send = address[0] + " "+AESplainText
                broadcast(message_to_send,connection,AESkey)

            else:
                remove(connection)
        except:
            continue

def broadcast(message,connection,AESkey):
    for clients in clientList:
        if clients != connection:
            try:
                AEScipherText = encryptAES(messageOut, AESkey)
                AESplainText = decryptAES(AEScipherText, AESkey)
                #connection.send(AEScipherText)
                clients.send(AEScipherText)
            except:
                clients.close()
                remove(clients)

def remove(connection):
    if connection in clientList:
        clientList.remove(connection)

def main():
    global RECVBUFFER
    RECVBUFFER = 2048
    global n
    n = 128
    global privateKey
    privateKey = []
    global publicKey
    publicKey = []
    if len(sys.argv) != 3 :
        print "USAGE: python file, IP, PORT"
        exit()

    IP = str(sys.argv[1])
    PORT = int(sys.argv[2])
    print "Generating Public and Private key"
    keyGenerate(n)
    print "Attempting to create server at " + IP + " located at",
    print PORT
    chatServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chatServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    chatServer.bind((IP,PORT))
    chatServer.listen(100)
    connection,address = chatServer.accept()
    print "Server created and listening on",
    print PORT
    print address[0] + " connected"
    sendPublicKey = ",".join(str(e) for e in publicKey)
    connection.send(sendPublicKey)
    sendCipherTextKey = connection.recv(RECVBUFFER)
    cipherTextKey = long(sendCipherTextKey)
    plainTextKey = decryption(cipherTextKey,privateKey)
    AESkey = arrayToKey(plainTextKey)
    global clientList
    clientList = []
    while True:
        sockets_list = [sys.stdin,connection]
        read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])
        for socks in read_sockets:
            if socks == connection:
                messageIn = socks.recv(2048)
                if messageIn:
                    #print messageIn
                    #print AESkey
                    #connection,address = chatServer.accept()
                    clientList.append(connection)
                    AESplainText = decryptAES(messageIn, AESkey)
                    print "Client Response: ",
                    print AESplainText
                else:
                    print "Error"
                    exit()
            else:
                messageOut = sys.stdin.readline()
                if messageOut:
                    AEScipherText = encryptAES(messageOut, AESkey)
                    AESplainText = decryptAES(AEScipherText, AESkey)
                    #print "test"
                    #print AESplainText
                    #print "test2"
                    #print AEScipherText
                    #broadcast(AEScipherText,connection)
                    connection.send(AEScipherText)
                    #print messageOut
                    #conn.send(messageOut)'''

    connection.close
    chatServer.close

main()
