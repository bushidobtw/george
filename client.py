import socket
import threading

HOST = '192.168.1.243'
PORT = 5555

# getting messages
def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(message)
        except:
            print("Disconnection.")
            client_socket.close()
            break

# connecting to server
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # getting name
    print(client_socket.recv(1024).decode('utf-8'))
    username = input("Enter user's name: ")
    client_socket.send(username.encode('utf-8'))

    print(client_socket.recv(1024).decode('utf-8'))
    role = input("Enter are you a student, teacher or director: ")
    client_socket.send(role.encode('utf-8'))

    if role == 'student' or role == 'teacher':
        print(client_socket.recv(1024).decode('utf-8'))
        class_name = input("Enter your class: ")
        client_socket.send(class_name.encode('utf-8'))

    # thread for receiving messages
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    # loop for sending messages
    while True:
        message = input("")
        if message.lower() == "exit":
            client_socket.close()
            break
        client_socket.send(message.encode('utf-8'))


start_client()