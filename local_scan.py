import socket
import threading
import queue
import json

def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.4)
        sock.connect((target, port))
        results.put(port)
    except:
        pass
    finally:
        sock.close()

def run_fast_scan(target, ports=None):
    if ports is None:
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 587, 993, 995, 1723, 3306,
            3389, 5900, 8080, 8443
        ]

    results = queue.Queue()
    threads = []

    for port in ports:
        t = threading.Thread(target=scan_port, args=(target, port, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    open_ports = sorted(list(results.queue))
    return open_ports


def run_full_scan(target, start_port=1, end_port=1024):
    results = queue.Queue()
    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port, results))
        threads.append(t)
        t.start()

        # throttle slightly to avoid overwhelming Render
        if port % 200 == 0:
            for x in threads:
                x.join()
            threads = []

    for t in threads:
        t.join()

    open_ports = sorted(list(results.queue))
    return open_ports
