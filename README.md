# SimpleComm Design Documentation

## Server Perspective
1. Load up config
2. Setup a thread and have it handle only incoming connections
    * To check the client's purpose, have client send in inital message byte
        * 0x1 - Authenticates as chat client (require chat OID)
        * 0x2 - Authenticates as file upload client (require file upload OID)
        * 0x3 - Authenticates as file request client (require chat OID)
3. Setup thread to accept user message or upload
4. Setup thread to relay the messages among the users
### TODO
* Finish Client Disconnection Checks
* File Upload Feat

## Client Perspective