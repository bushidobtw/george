import socket
import threading

HOST = '192.168.1.243'
PORT = 5555

clients = []
user_roles = {}
user_classes = {}


# message to everyone
def broadcast(message, sender_socket=None):
    for client in clients:
        if client != sender_socket:
            client.send(message)


# message to students
def class_broadcast(message, class_name, sender_socket=None):
    for client in clients:
        if user_classes.get(client) == class_name and client != sender_socket:
            client.send(message)


def handle_client(client_socket):
    try:

        client_socket.send("Enter user's name:".encode('utf-8'))
        username = client_socket.recv(1024).decode('utf-8')

        client_socket.send("Enter if you are a student, teacher or director:".encode('utf-8'))
        role = client_socket.recv(1024).decode('utf-8')

        if role == 'student' or role == 'teacher':
            client_socket.send("Enter name of your class:".encode('utf-8'))
            class_name = client_socket.recv(1024).decode('utf-8')
        else:
            class_name = "all"

        user_roles[client_socket] = role
        user_classes[client_socket] = class_name

        welcome_message = f"{username} ({role}) connected!"
        print(welcome_message)
        broadcast(welcome_message.encode('utf-8'), client_socket)

        # loop for messages
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break

            # for director
            if role == 'director':
                broadcast(f" Director {username} send: {message}".encode('utf-8'), client_socket)

            # teacher to class
            elif role == 'teacher':
                class_broadcast(f" Teacher {username} send: {message}".encode('utf-8'), class_name, client_socket)

            # Students for teacher
            elif role == 'student':
                for client, client_role in user_roles.items():
                    if client_role == 'teacher' and user_classes[client] == class_name:
                        client.send(f" Student {username} send: {message}".encode('utf-8'))
                        break

    except:
        print(username)

    finally:
        clients.remove(client_socket)
        broadcast(f"{username} disconnected.".encode('utf-8'), client_socket)
        client_socket.close()


# start server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"server: {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"New connection: {addr}")

        clients.append(client_socket)

        # thread for client
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()



start_server()