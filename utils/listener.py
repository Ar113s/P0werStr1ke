import socket
import threading
import sys

# Basic Listener who is interactive and can wait for shells in the background. Is called with --listener PORT

class Listener:
    def __init__(self, port):
        self.port = port
        self.socket = None
        self.running = False
        
    def start(self):
        """Start the listener on the specified port"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.running = True
            
            print(f"[+] Listener started on port {self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    print(f"[+] Connection received from {address[0]}:{address[1]}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error:
                    if self.running:
                        print("[-] Socket error occurred")
                        
        except Exception as e:
            print(f"[-] Error starting listener: {e}")
            
    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        try:
            while True:
                command = input(f"shell@{address[0]}> ")
                
                if command.lower() in ['exit', 'quit']:
                    break
                    
                client_socket.send((command + '\n').encode())
                response = client_socket.recv(4096).decode('utf-8', errors='ignore')
                print(response, end='')
                
        except Exception as e:
            print(f"[-] Error handling client: {e}")
        finally:
            client_socket.close()
            print(f"[-] Connection closed with {address[0]}")
            
    def stop(self):
        """Stop the listener"""
        self.running = False
        if self.socket:
            self.socket.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python listener.py PORT")
        sys.exit(1)
        
    try:
        port = int(sys.argv[1])
        listener = Listener(port)
        listener.start()
    except KeyboardInterrupt:
        print("\n[-] Listener stopped")
    except ValueError:
        print("[-] Invalid port number")

if __name__ == "__main__":
    main()