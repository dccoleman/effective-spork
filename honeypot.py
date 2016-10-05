
from BaseHTTPServer import BaseHTTPRequestHandler
import datetime
import signal
import socket
from StringIO import StringIO
import time


APP_ADDR = "10.4.12.2"
APP_PORT = 44044

quitting = False


def on_signal(signum, frame):
    global quitting
    quitting = True


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message


def get_http_response(content, content_type):
    return (
        "HTTP/1.1 200 OK\r\n" +
        "Content-Type: " + content_type + "; charset=utf-8\r\n" +
        "Content-Length: " + `len(content)` + "\r\n" +
        "Connection: Closed\r\n" +
        "\r\n" +
        content
    ) 


def get_http_404():
    return (
        "HTTP/1.1 404 Not Found\r\n" +
        "\r\n" +
        "404: Page not found"
    )


def get_http_redirect(redirect_url):
    return (
        "HTTP/1.1 303 See Other\r\n" +
        "Location: "  + redirect_url + "\r\n" + 
        "\r\n" + 
        "Redirecting to Web server..."
    )


def send_port_to_appliance(port):
    app_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    app_sock.connect((APP_ADDR, APP_PORT))
    hi_byte = (port << 8) & 0xff
    lo_byte = port & 0xff
    app_sock.send(chr(hi_byte) + chr(lo_byte))
    app_sock.close()


def main():
    signal.signal(signal.SIGINT, on_signal)

    with open('honeypot.html', 'r') as f:
        honeypot_html = f.read()
    with open('captcha.png', 'rb') as f:
        captcha_image = f.read()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('0.0.0.0', 80))
    server_sock.listen(5)
    server_sock.setblocking(0)

    while not quitting:
        try:
            client_sock, (client_addr, client_port) = server_sock.accept()
        except:
            try:
                time.sleep(0.1)
            except:
                pass
            continue
        print 'connected to ' + `client_addr` + ':' + `client_port`

        data = ''
        fails = 0
        while fails < 3:
            try:
                read = client_sock.recv(1024)
            except:
                fails += 1
                time.sleep(0.1)
                continue
            if len(read) == 0:
                fails += 1
                continue
            data += read

        print data

        try:
            request = HTTPRequest(data)
        except:
            continue
        if request.command == 'GET':
            if request.path == '/':
                client_sock.send(get_http_response(honeypot_html, 'text/html'))
            elif request.path == '/captcha.png':
                client_sock.send(get_http_response(captcha_image, 'image/png'))
            elif request.path.startswith('/captcha-form?'):
                if request.path.count('captcha-answer=overlooks+inquiry') > 0:
                    send_port_to_appliance(client_port)
                    time.sleep(2)
                    client_sock.send(get_http_redirect('http://www.cap.com/'))
                else:
                    client_sock.send(get_http_response(honeypot_html, 'text/html'))
            else:
                client_sock.send(get_http_404())
        else:
            client_sock.send(get_http_404())
        client_sock.close()

main()
