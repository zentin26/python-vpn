from .frame import Frame


class IPsecFrame(Frame):
    pass
    
    
class IPsecServer():
    def __init__(self, port=500):
        self.port = port
    
    def handle_frame(self, data):
        return
        
    def shutdown(self):
        return True
