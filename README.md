Quickie WIP ransomware program.

Please use for good (aka security learning and teaching).

If it is not obvious:

!!!DO NOT RUN ON A MACHINE YOU CARE ABOUT OR A MACHINE THAT IS NOT YOURS!!!

Server is a basic python tcp server that accepts connections that send a RSA public key. Server generates a uid and AES256 key/iv and sends them to the client.

Server requires pycrypto (pip install pycrypto).

Ransom is a no-dependency (other than ws2_32 on windows...) c++ program that opens a socket connection, generates a RSA 4096 public and private key pair. Ransom sends the public key through the socket and receives a UID and an AES256 key/iv. It uses the key and iv to encrypt all files in a given directory.

Unransom is also a no-dependency c++ program that asks for a directory, key, and iv and then decrypts any ransomed files.

Note: These take a LONG time to compile! This is because of CryptoPP. If you want to experiment with this, I'd recommend compiling everything in client/include/cryptopp as .o files and linking with those instead of recompiling every time...

To do:

- Check on licenses...
- Store information on the server in a database file (well...probably just a flat-file...).
