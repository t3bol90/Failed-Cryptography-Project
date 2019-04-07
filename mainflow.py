import hashlib
from os import system
from random import randint
from time import sleep, perf_counter

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import getpass

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

S_WELCOME = '''
                         __      __       .__                               
                        /  \    /  \ ____ |  |   ____  ____   _____   ____  
                        \   \/\/   // __ \|  | _/ ___\/  _ \ /     \_/ __ \ 
                         \        /\  ___/|  |_\  \__(  <_> )  Y Y  \  ___/ 
                          \__/\  /  \___  >____/\___  >____/|__|_|  /\___  >
                               \/       \/          \/            \/     \/ '''

S_TITLE = '''
.------..------..------..------..------..------..------..------..------..------..------..------.
|C.--. ||R.--. ||Y.--. ||P.--. ||T.--. ||O.--. ||G.--. ||R.--. ||A.--. ||P.--. ||H.--. ||Y.--. |
| :/\: || :(): || (\/) || :/\: || :/\: || :/\: || :/\: || :(): || (\/) || :/\: || :/\: || (\/) |
| :\/: || ()() || :\/: || (__) || (__) || :\/: || :\/: || ()() || :\/: || (__) || (__) || :\/: |
| '--'C|| '--'R|| '--'Y|| '--'P|| '--'T|| '--'O|| '--'G|| '--'R|| '--'A|| '--'P|| '--'H|| '--'Y|
`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'`------`'''

S_WRONGINP = '''WRONG INPUT! PLEASE TRY AGAIN'''

S_LOGINERR = '''OOPS! SOME THING WENT WRONG'''

key = 'abcdefghijklmnopqrstuvwxyz'


def goodbye():
    print("GUD BYE :)")
    print("Have a nice day")
    print("Press Enter to confirm exit!")
    input()

def output(text):
    fileout = open('output.txt', 'w')
    fileout.write(str(text))
    fileout.close()
# hàm load file account.txt và save vào account_hash.txt (For testing)
def hash_txt_save():
    filein = open('account.txt', 'r')
    a = filein.readlines()
    i = 0
    while i < len(a):
        hash_array = hashlib.sha256(a[i].rstrip('\n').encode())
        wow = hash_array.hexdigest()
        fileout = open('account_hash.txt', 'a')
        fileout.write(wow + '\n')
        i = i + 1


# hash_txt_save()
# hàm thêm một account mới

# hàm read file

def readfile():
    f = open('input.txt', 'r')
    t = f.read()
    f.close()
    return t


def create_username_password():
    print("SIGN UP")
    print("user name: ")
    temp_user_name = input().rstrip('\n')
    user_name = temp_user_name
    hash_user = hashlib.sha256(user_name.encode())
    hash_user_name = hash_user.hexdigest()

    print("password: ")
    password = input().rstrip('\n')
    hash_pass = hashlib.sha256(password.encode())
    hash_password = hash_pass.hexdigest()

    filein = open('account_hash.txt', 'r')
    a = filein.readlines()  # đọc từng dòng vd: a[0] sẽ là dòng đầu tiên
    # mảng a chứa user name và password
    i = 0
    # while này là thêm vào account_hash
    while i < len(a):
        if a[i].rstrip('\n') == hash_user_name:  # kiểm tra user có tồn tại hay chưa
            print("account already exists ")
            create_username_password()
            break;

        if i == len(a) - 1:  # đọc tới cuối file nếu ko khớp thì tạo mới
            fileout = open('account_hash.txt', 'a+')  # ghi vào cuối file
            fileout.write(hash_user_name + '\n')
            fileout.write(hash_password + '\n')

            print("Add successfully")
            sleep(2)
            return True
        i = i + 1


# SHIFTING
def encrypt1(n, plaintext):
    """Encrypt the string and return the ciphertext"""
    result = ''
    for l in plaintext:
        try:
            i = (key.index(l) + n) % len(key)
            result += key[i]
        except ValueError:
            result += l
    return result


def decrypt1(n, ciphertext):
    """Decrypt the string and return the plaintext"""
    result = ''

    for l in ciphertext:
        try:
            i = (key.index(l) - n) % len(key)
            result += key[i]
        except ValueError:
            result += l
    return result


def encrypt2(message):
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(message.encode())
    return (key, token)


def decrypt2(key, token):
    f = Fernet(key)
    text = f.decrypt(token)
    return text


def encrypt3(message):
    ciphertext = public_key.encrypt(message.encode(),
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                 label=None))
    return ciphertext


def decrypt3(ciphertext):
    plaintext = private_key.decrypt(ciphertext,
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                 label=None))
    return plaintext


def login():
    filein = open('account_hash.txt', 'r')
    a = filein.readlines()
    print("LOGIN")

    print("user name: ")
    user_name = input().rstrip('\n')
    hash_user = hashlib.sha256(user_name.encode())
    hash_user_name = hash_user.hexdigest()

    password = getpass.getpass(prompt="password:\n").rstrip('\n')
    hash_pass = hashlib.sha256(password.encode())
    hash_password = hash_pass.hexdigest()

    filein = open('account_hash.txt', 'r')
    a = filein.readlines()
    i = 0

    while i < len(a):

        if (a[i].rstrip('\n') == hash_user_name) and (a[i + 1].rstrip('\n') == hash_password):
            print("Login successfully ")
            return True

        if i == len(a) - 1:
            print("Login Failed")
            sleep(2)
            return False
        i = i + 1


def userOption():
    system('cls')
    print(S_WELCOME)
    print(S_TITLE)
    print("\n\t[L]ogin")
    print("\n\t[S]ign up")
    print("\n\t[E]xit")
    user_input = ''
    while len(user_input) != 1:
        print("\nUser option ")
        user_input = input(':').rstrip('\n')
    guess_in_lower = user_input.lower()
    return guess_in_lower


def menu3(type):
    system('cls')
    if (type == 0):
        text = readfile()
        print("[1] Encrypt 1 (Shifting) {15 minutes/50MB file test}\n")
        print("[2] Encrypt 2 (Fernet)   {Approximately 2~3s\n")
        print("[3] Encrypt 3 (RSA)      {Cant use with file too large (2KB is a large file :))!}\n")
        print("[E]xit\n")
        user_input = ''
        while len(user_input) != 1:
            user_input = input(':').rstrip('\n')
        guess_in_lower = user_input.lower()
        if guess_in_lower == '1':
            system('cls')
            print("[1] Encrypt 1 (Shifting)\n")
            n = randint(0, 225)
            print("Key shifting : ", n)
            t0 = perf_counter()
            cypher = encrypt1(n, text)
            t1 = perf_counter()
            output(cypher)
            if len(text) < 256:
                print("Text after decrypt: ", decrypt1(n, cypher))
            print(t1 - t0, " secs")
        elif guess_in_lower == '2':
            system('cls')
            print("[2] Encrypt 2 (Fernet)\n")
            t0 = perf_counter()
            (Fernet_key, Fernet_token) = encrypt2(text)
            t1 = perf_counter()
            print("Key: ", Fernet_key)
            output(Fernet_token)
            if len(text) < 256:
                print("Text after decrypt: ", decrypt2(Fernet_key, Fernet_token))
            print(t1 - t0, " secs")
            input()
        elif guess_in_lower == '3':
            if len(text) < 255:
                system('cls')
                t0 = perf_counter()
                print("[2] Encrypt 3 (RSA)\n")
                cypher = encrypt3(text)
                t1 = perf_counter()
                print(t1 - t0, " secs")
                # print("\nPrivated key : ", private_key)
                # print("\nPublic key   : ", public_key)
                output(cypher)
                print("\nText after decrypt: ", decrypt3(cypher))
                input()
            else:
                print("RSA is limited for keysize = 2048!")
                input()
        elif guess_in_lower == 'e':
            goodbye()
            exit(0)
        else:
            print(S_WRONGINP)
            input()
            menu3(1)
    if (type == 1):
        print("Please input plaintext to encrypt: ")
        text = input()
        system('cls')
        print("[1] Encrypt 1 (Shifting)\n")
        print("[2] Encrypt 2 (Fernet)  \n")
        print("[3] Encrypt 3 (RSA)      \n")
        print("[E] xit\n")
        user_input = ''
        while len(user_input) != 1:
            user_input = input(':').rstrip('\n')
        guess_in_lower = user_input.lower()
        if guess_in_lower == '1':
            system('cls')
            print("[1] Encrypt 1 (Shifting)\n")
            n = randint(0, 225)
            t0 = perf_counter()
            cypher = encrypt1(n, text)
            t1 = perf_counter()
            print("Key shifting : ", n)
            print("Cypher :", cypher)
            print("Text after decrypt: ", decrypt1(n, cypher))
            print(t1 - t0, " secs")
        elif guess_in_lower == '2':
            system('cls')
            print("[2] Encrypt 2 (Fernet)\n")
            t0 = perf_counter()
            (Fernet_key, Fernet_token) = encrypt2(text)
            t1 = perf_counter()
            print("Key: ", Fernet_key)
            print("Token: ", Fernet_token)
            print("Text after decrypt: ", decrypt2(Fernet_key, Fernet_token))
            print(t1 - t0, " secs")
        elif guess_in_lower == '3':
            if len(text) < 214:
                system('cls')
                print("[2] Encrypt 3 (RSA)\n")
                t0 = perf_counter()
                cypher = encrypt3(text)
                t1 = perf_counter()
                print(t1 - t0, " secs")
                # print("\nPrivated key : ", private_key)
                # print("\nPublic key   : ", public_key)
                print("\nCyphertext: ", cypher)
                print("\nText after decrypt: ", decrypt3(cypher))
            else:
                print("RSA is limited for keysize = 2048!")
                input()
        elif guess_in_lower == 'e':
            goodbye()
            exit(0)
        else:
            print(S_WRONGINP)
            input()
            menu3(1)
    print("Do you want to continue? (y/n)")
    user_input = ''
    while len(user_input) != 1:
        user_input = input(':').rstrip('\n')
    guess_in_lower = user_input.lower()
    if guess_in_lower == 'y':
        menu2(True)
    else:
        goodbye()
        exit(0)


def menu2(boolean):
    system('cls')
    if (boolean):
        # 0: File, 1: Text
        print(S_TITLE)
        print("\n[F]ile encrypt")
        print("\n[T]ext encrypt")
        print("\n[E]xit")
        print("\nUser option: ")
        user_input = ''
        while len(user_input) != 1:
            user_input = input(':').rstrip('\n')
        guess_in_lower = user_input.lower()
        if guess_in_lower == 'f':
            menu3(0)
        elif guess_in_lower == 't':
            menu3(1)
        elif guess_in_lower == 'e':
            goodbye()
            exit(0)
        else:
            print(S_WRONGINP)
            input()
            menu2(True)
    else:
        print(S_LOGINERR)
        input()
        menu2(menu(userOption()))


def menu(user_input):
    if user_input == 'l':
        return login()
    elif user_input == 's':
        return create_username_password()
    elif user_input == 'e':
        goodbye()
        exit(0)
    else:
        print(S_WRONGINP)
        input()
        menu(userOption())


menu2(menu(userOption()))
