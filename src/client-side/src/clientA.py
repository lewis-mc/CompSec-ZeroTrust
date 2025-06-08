from client_init import Client
from connection_management import ConnectionManager

def test():
    clientA = Client("clientA")
    clientA.start()
    
test()