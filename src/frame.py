from twisted.internet.task import LoopingCall
from twisted.internet import reactor, protocol

class FrameReciver(protocol.DatagramProtocol):
    def __init__(self, server, frame_class):
        self.server = server
        self.frame_class = frame_class
        
    def datagramReceived(self, data, host):
        F = self.frame_class(self.transport, data, host)
        self.server.handle_frame(F)
        
        
class Frame:
    def __init__(self, transport, data, host):
        self.transport = transport
        self.host = host
        self.parse_data(data)
        
    def parse_data(self, data):
        self.data = data
        
    def reply(self, data):
        self.transport.write(data, self.host)