# Simplified SSL (Secure Socket Layer) #

You will have a Server and a client

The Server functions as a one way communication device that only the client can interact with locally on your computer

The Server:

* Must authorize the client by using a handshake algorithm after decrypting request data received by client
* Must encrypt data sent to client using an RSA encryption algorithm
* Must decrypt data received from client using an RSA decryption algorithm
* Must continuosly run until clients says the key word to close the connection

The Client:
* Must send encrypted data to perform the handshake with the server
* Must encrypt data sent to server using an RSA encryption algorithm
* Must decrypt data received from server using an RSA decryption algorithm
* Must continuosly run until user says the key word to send to server to close the connection

