#!/usr/bin/env python3
"""
=============================================================================
PANELX ULTRA-SPEED WEBSOCKET / HTTP PROXY ENGINE
Optimized for Low Latency, TCP_NODELAY, Fast Socket Streaming & BBR
=============================================================================
"""
import socket
import threading
import select
import sys
import os

LISTEN_PORTS = [80, 8080, 443, 8880]
SSH_PORT = 22
BUFFER_SIZE = 32768  # 32KB high-throughput buffer

def tune_socket(sock):
    try:
        # Disable Nagle algorithm for ultra-low latency interactive tunneling
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Optimal buffer sizing
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        # Keepalive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass

def handle_client(client_socket, client_addr):
    target_socket = None
    try:
        tune_socket(client_socket)

        # Read the initial HTTP request / WebSocket Handshake
        request = client_socket.recv(4096)
        if not request:
            client_socket.close()
            return

        # Connect to the local OpenSSH daemon
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tune_socket(target_socket)
        target_socket.connect(('127.0.0.1', SSH_PORT))

        # If it is an HTTP or WebSocket upgrade request, send standard 101 Switching Protocols response
        if b"Upgrade: websocket" in request or b"HTTP/" in request or b"GET " in request or b"CONNECT " in request:
            handshake_response = (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Server: PanelX-WsProxy/2.0-Turbo\r\n"
                b"\r\n"
            )
            client_socket.sendall(handshake_response)
        else:
            # Otherwise forward the raw packet to SSH
            target_socket.sendall(request)

        # High-performance Bi-directional stream forwarding
        sockets = [client_socket, target_socket]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 300)
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
        except Exception:
            pass
        if target_socket:
            try:
                target_socket.close()
            except Exception:
                pass

def listen_on_port(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tune_socket(server)
    try:
        server.bind(('0.0.0.0', port))
        server.listen(1024)
        print(f"[PanelX WS-Proxy] Listening on port {port} -> SSH:{SSH_PORT} (Turbo BBR Optimized)")
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
    except Exception as e:
        print(f"[PanelX WS-Proxy] Could not bind to port {port}: {e}")

def main():
    ports = LISTEN_PORTS
    if "WS_PORTS" in os.environ:
        try:
            ports = [int(p.strip()) for p in os.environ["WS_PORTS"].split(",") if p.strip()]
        except Exception:
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
