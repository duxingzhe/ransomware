Quickie WIP ransomware program.

Please use for good (aka security learning and teaching).

If it is not obvious:

!!!DO NOT RUN ON A MACHINE YOU CARE ABOUT OR A MACHINE THAT IS NOT YOURS!!!

Server is a basic python tcp server that accepts connections that send a RSA public key. Server generates a uid and AES256 key/iv and sends them to the client.

Client is a no-dependency (other than ws2_32 on windows...) c++ program that opens a socket connection, generates a RSA 4096 public and private key pair. The client sends the public key through the socket and receives a UID and an AES256 key/iv. It uses the key and iv to encrypt all files in a given directory.

To do:

- Test on windows (definitely doesn't compile since I'm missing -lws2_32 on the flags...but I'll get to that when I test this on windows)...
- Check on licenses...
- Store information on the server in a database file (well...probably just a flat-file...).
