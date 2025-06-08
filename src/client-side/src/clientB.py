from client_init import Client
from connection_management import ConnectionManager

def test():
    clientB = Client("clientB")
    clientB.start()
    
test()