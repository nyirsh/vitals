"""The TLS server vitals-ssl's host tests connect to: on its port, after the handshake it sends
the name the client asked for (SNI) as "sni=<name>\n" ("sni=-" without one), then echoes each line
back. "quit\n" ends the connection with close_notify, and "drop\n" closes the socket without it.
The next port accepts and never answers, for timeouts. With a second certificate and key, the port
after that serves them the same way (a chain a CA signed)."""
import socket
import ssl
import sys
import threading


def remember(connection, name, _):
    connection.vs_name = name


def serve_echo(listener, context):
    context.sni_callback = remember
    while True:
        raw, _ = listener.accept()
        threading.Thread(target=echo, args=(raw, context), daemon=True).start()


def echo(raw, context):
    try:
        connection = context.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError):
        raw.close()
        return
    try:
        connection.sendall(("sni=%s\n" % (getattr(connection, "vs_name", None) or "-")).encode())
        pending = b""
        while True:
            data = connection.recv(4096)
            if not data:
                break
            pending += data
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if line == b"quit":
                    connection.sendall(b"bye\n")
                    connection.unwrap().close()
                    return
                if line == b"drop":
                    connection.sendall(b"bye\n")
                    raw.shutdown(socket.SHUT_RDWR)
                    raw.close()
                    return
                connection.sendall(line + b"\n")
    except (ssl.SSLError, OSError):
        pass
    finally:
        try:
            connection.close()
        except OSError:
            pass


def serve_silent(listener):
    kept = []
    while True:
        raw, _ = listener.accept()
        kept.append(raw)


def server_context(certificate, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    return context


def main():
    port, certificate, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    context = server_context(certificate, key)
    chained = server_context(sys.argv[4], sys.argv[5]) if len(sys.argv) > 5 else None
    listeners = []
    for offset in range(3 if chained else 2):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port + offset))
        listener.listen(16)
        listeners.append(listener)
    threading.Thread(target=serve_echo, args=(listeners[0], context), daemon=True).start()
    threading.Thread(target=serve_silent, args=(listeners[1],), daemon=True).start()
    if chained:
        threading.Thread(target=serve_echo, args=(listeners[2], chained), daemon=True).start()
    print("ready", flush=True)
    threading.Event().wait()


main()
