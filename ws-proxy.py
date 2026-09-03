import socket
import threading
import select
import sys
import os

LISTEN_PORTS = [80, 8080, 443, 8880]
SSH_PORT = 22
BUFFER_SIZE = 8192

def handle_client(client_socket, client_addr):
    target_socket = None
    try:
        # Read the initial HTTP request / WebSocket Handshake
        request = client_socket.recv(4096)
        if not request:
            client_socket.close()
            return

        # Connect to the local OpenSSH daemon
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect(('127.0.0.1', SSH_PORT))

        # If it is an HTTP or WebSocket upgrade request, send standard 101 Switching Protocols response
        if b"Upgrade: websocket" in request or b"HTTP/" in request or b"GET " in request or b"CONNECT " in request:
            handshake_response = (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Server: PanelX-WsProxy/1.0\r\n"
                b"\r\n"
            )
            client_socket.sendall(handshake_response)
        else:
            # Otherwise forward the raw packet to SSH
            target_socket.sendall(request)

        # Bi-directional stream forwarding
        sockets = [client_socket, target_socket]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 60)
            if exceptional or not readable:
                break

            for s in readable:
                other = target_socket if s is client_socket else client_socket
                data = s.recv(BUFFER_SIZE)
                if not data:
                    return
                other.sendall(data)

    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass
        if target_socket:
            try:
                target_socket.close()
            except:
                pass

def listen_on_port(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', port))
        server.listen(256)
        print(f"[PanelX WS-Proxy] Listening on port {port} -> SSH:{SSH_PORT}")
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
    except Exception as e:
        print(f"[PanelX WS-Proxy] Could not bind to port {port}: {e}")

def main():
    # Read custom ports from environment or args if provided
    ports = LISTEN_PORTS
    if "WS_PORTS" in os.environ:
        try:
            ports = [int(p.strip()) for p in os.environ["WS_PORTS"].split(",") if p.strip()]
        except:
            pass

    threads = []
    for port in ports:
        t = threading.Thread(target=listen_on_port, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    print(f"[PanelX WS-Proxy] Running multi-port proxy on {ports}. Forwarding to 127.0.0.1:{SSH_PORT}")
    threading.Event().wait()

if __name__ == "__main__":
    main()
