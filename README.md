# CompSec-ZeroTrust
A cryptographically secure file server that allows users to store, retrieve, and share files. This challenge aims to replicate some of the problems faced when managing files storage on cloud-based service solutions, and the security concerns that arise when doing so.

# How to run:


## Create two seperate Python Virtual Environments in seperate terminals:

1. python3 -m venv client_env
2. python3 -m venv server_env

## Install requirements, in each environment:

 - pip install -r requirements.txt


## To run Server (perform first):

1. Navigate to ../src/server-side/src
2. Execute python3 server.py

## To run client:

1. Navigate to ../src/client-side/src
2. Execute python3 clientA.py. This generates a client that awaits input from user to determine aciton:
    - 1 <file_name> : uploads <file_name> to Server (file to transfer needs to be in  '../client-side/clients/<client_name>/storage' directory)
    - 2 <file_name> : retrieves <file_name> from Server 
    - 3 <file_name> <client(s)> : shares <file_name> with <client(s)>
