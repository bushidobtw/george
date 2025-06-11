# client_thread.py
import socket
import threading

received_messages = []

def start_client_socket(username, role, class_name):
    def listen():
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', 5555))

        client.recv(1024)  # "Enter user's name:"
        client.send(username.encode())

        client.recv(1024)  # "Enter are you a student, teacher or director:"
        client.send(role.encode())

        if role in ['student', 'teacher']:
            client.recv(1024)  # "Enter your class:"
            client.send(class_name.encode())

        while True:
            try:
                msg = client.recv(1024).decode()
                if msg:
                    received_messages.append(msg)
            except:
                break

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()