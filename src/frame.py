from twisted.internet.task import LoopingCall
from twisted.internet import reactor, protocol

class FrameReceiver(protocol.DatagramProtocol):
    """Recieves incoming datagrams and passes them to the server the specificied frame class"""
    def __init__(self, server, frame_class):
        self.server = server
        self.frame_class = frame_class
        
    def datagramReceived(self, data, host):
        F = self.frame_class(self.transport, data, host)
        self.server.handle_frame(F)
        
        
class Frame:
    """Base frame class"""
    def __init__(self, transport, data, host):
        self.transport = transport # the data channel
        self.host = host # the sending host
        self.parse_data(data)
        
    def parse_data(self, data):
        # to be over-written
        self.data = data
        
    def reply(self, data):
        # to be over-written
        self.transport.write(data, self.host)
