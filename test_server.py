from http.server import HTTPServer, BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        message = b"Hello from my local packet sniffing lab!"
        self.wfile.write(message)

    def log_message(self, format, *args):
        return


server = HTTPServer(("127.0.0.1", 8000), Handler)

print("Local server running at http://127.0.0.1:8000")

server.serve_forever()
