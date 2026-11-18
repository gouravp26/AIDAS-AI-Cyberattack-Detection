import socket
import threading
import time

import webview
from dashboard.app import app


HOST = "127.0.0.1"
PORT = 5000


def start_server():
    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False,
    )


def wait_for_server(timeout=60):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)

    return False


if __name__ == "__main__":
    server_thread = threading.Thread(
        target=start_server,
        daemon=True,
    )
    server_thread.start()

    if not wait_for_server():
        raise RuntimeError("AIDAS server failed to start.")

    webview.create_window(
        title="AIDAS | AI Cyberattack Detection System",
        url=f"http://{HOST}:{PORT}",
        width=1440,
        height=900,
        min_size=(1000, 650),
        resizable=True,
    )

    webview.start(debug=False)
