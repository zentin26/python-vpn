import bitstruct
import socket
from .frame import Frame
from .utils import *

# initiate globals
l2tp_header_formatter = bitstruct.compile('b1b1p2b1p1b1b1p4u4u16u16u16u16u16') 
avp_header_formatter = bitstruct.compile('b1b1p4u10u16u16')

avp_attribute_types = [(0,  'control_message',      'u16'), 
                       (2,  'protocol_version',     'u8u8'), 
                       (3,  'framing_capabilities', 'p30b1b1'),
                       (4,  'bearer_capabilities',  'p30b1b1'),
                       (6,  'firmware_revision',    'u16'),
                       (7,  'host_name',            't{len}'),
                       (8,  'vendor_name',          't{len}'), 
                       (9,  'assigned_tunnel_id',   'u16'),
                       (10, 'receive_window_size',  'u16'),
                       ] # attribute_type, name, unpack string
                       
control_message_types = [(1,  'SCCRQ'),   # Start-Control-Connection-Request
                         (2,  'SCCRP'),   # Start-Control-Connection-Reply
                         (3,  'SCCCN'),   # Start-Control-Connection-Connected
                         (4,  'StopCNN'), # Stop-Control-Connection-Notification
                         (6,  'HELLO'),   # Hello
                         (7,  'OCRQ'),    # Outgoing-Call-Request
                         (8,  'OCRP'),    # Outgoing-Call-Reply
                         (9,  'OCCN'),    # Outgoing-Call-Connected
                         (10, 'ICRQ'),    # Incoming-Call-Request
                         (11, 'ICRO'),    # Incoming-Call-Reply
                         (12, 'ICCN'),    # Incoming-Call-Connected
                         (14, 'CDN'),     # Call-Disconnect-Notify
                         (20, 'ACK')      # Explicit Acknowledgement                   
                         ] # control_message_type, name
                         
                         
class L2TPFrame(Frame):
    """The L2TP Frame"""
    avps = {}

    def parse_data(self, data):
        # unpack header
        (self.message_type, 
        _,
        _,    
        _,
        _,
        self.protocol_version,
        self.length, 
        self.tunnel_id, 
        self.session_id, 
        self.control_sequence_id, 
        self.expected_control_sequence_id) = l2tp_header_formatter.unpack(data[:12])
        self._data = data[12:]
       
        if (self.message_type == True) and (len(self._data) != 0):
            # if this is a control message and it contains an AVP
            avps = self._data
        
            # format and parse attribute-value pairs
            while len(avps) > 0:
                # unpack header and AVP value
                mandatory, hidden, length, vid, attribute_type = avp_header_formatter.unpack(avps[:6])
                data = avps[6:length]
                # get the AVP value name and unpack string
                _, name, fmt = index_tuples(avp_attribute_types, attribute_type)
                value = bitstruct.unpack(fmt.format(len=8*len(data)), data)
                if len(value) == 1:
                    # (value,) --> value
                    value = value[0]
                
                if name == 'control_message':
                    # parse control message type
                    _, value = index_tuples(control_message_types, value)
                
                # add to frame parsed AVPS
                self.avps[name] = (name, 
                                   value, 
                                   length, 
                                   vid, 
                                   mandatory, 
                                   hidden)
                # move onto to next AVP to parse
                avps = avps[length:]
        
        
    def reply(self, message_type, protocol_version, tunnel_id, session_id, control_sequence_id, expected_control_sequence_id, data=bytearray(), priority=False):
        # send a response to the frame sender
        length = 12+len(data)
        # pack the L2TP header
        message =  l2tp_header_formatter.pack(message_type, 
                                              True, 
                                              True, 
                                              False, 
                                              priority, 
                                              protocol_version, 
                                              length, 
                                              tunnel_id, 
                                              session_id, 
                                              control_sequence_id, 
                                              expected_control_sequence_id)
        # append the data
        message += data
        
        # send
        self.transport.write(message, self.host)
       
        
class L2TPServer:
    """The L2TP server class"""
    def __init__(self, protocol_version, port=1701):
        self.protocol_version = protocol_version
        self.port = port
        self.hostname = socket.gethostname()
        # send sequence counter
        _ns_counter = 0
        # expected next recieved counter
        _nr_counter = 1
        
        # handlers for the various control message types
        self.control_message_handlers = {'SCCRQ':   self.handle_sccrq, 
                                         'SCCCN':   self.handle_scccn, 
                                         'StopCNN': self.handle_stopcnn, 
                                         'OCRQ':    self.handle_ocrq, 
                                         'OCCN':    self.handle_occn, 
                                         'ICRQ':    self.handle_icrq, 
                                         'ICCN':    self.handle_iccn, 
                                         'CDN':     self.handle_cdn
                                         }

        
    def format_avps(self, avps):
        # format the AVPS for response message
        data = bytearray()
        for avp in avps:
            # get the attribute_type and pack string
            attribute_type, _, fmt = index_tuples(avp_attribute_types, avp[4], 1)
            avp_value = bitstruct.pack(fmt.format(len=8*len(str(avp[2][0]))), *avp[2]) # where len is the number of bits of the value
            
            # pack the header
            header = avp_header_formatter.pack(avp[0],                                       # mandatory
                                             avp[1],                                         # hidden
                                             6+len(avp_value),                               # length
                                             avp[3],                                         # vendor id
                                             index_tuples(avp_attribute_types, avp[4], 1)[0] # message type
                                             )
            
            data += header
            data += avp_value
            
        return data
        
    def handle_frame(self, frame):
        # handle the frame
        if frame.message_type:
            # if it is a control message
            if len(frame.avps) != 0:
                # if it has AVPS
                self._nr_counter += 1
                control_message_type = frame.avps['control_message'][1]
                self.control_message_handlers[control_message_type](frame)
            
        else:
            pass
          
        
    def handle_sccrq(self, frame):
        # handle the sccrq message
        # format the various AVPS
        avps = [(True, False, (index_tuples(control_message_types, 'SCCRP', 1)[0],), 0, 'control_message'),      # message type
                (True, False, (1, 0),                                                0, 'protocol_version'),     # protocol version
                (True, False, (False, True),                                         0, 'framing_capabilities'), # framing capabilities
                (True, False, (self.hostname,),                                      0, 'host_name'),            # system host name
                (True, False, (frame.avps['assigned_tunnel_id'][1],),                0, 'assigned_tunnel_id')    # tunnel id
                ] # manatory, hidden, value, vendor id, control message type
        data = self.format_avps(avps)
        
        # send reply
        frame.reply(True, 
                    self.protocol_version, 
                    frame.avps['assigned_tunnel_id'][1], 
                    frame.session_id, 
                    self._ns_counter, 
                    self._nr_counter,
                    data
                    )    
        self._ns_counter += 1
    
    def handle_scccn(self, frame):
        # handle the scccn message
        frame.reply(True, 
                    self.protocol_version, 
                    frame.avps['assigned_tunnel_id'][1], 
                    frame.session_id, 
                    frame.control_sequence_id, 
                    frame.expected_control_sequence_id,
                    )
        self._ns_counter += 1
        
    def handle_stopcnn(self, frame):
        pass
        
    def handle_ocrq(self, frame):
        pass
        
    def handle_occn(self, frame):
        pass
        
    def handle_icrq(self, frame):
        # handle the icrq message
        frame.reply(True, 
                    self.protocol_version, 
                    frame.avps['assigned_tunnel_id'][1], 
                    frame.session_id, 
                    frame.control_sequence_id, 
                    frame.expected_control_sequence_id,
                    )
        self._ns_counter += 1
        
    def handle_iccn(self, frame):
        # handle the iccn message
        frame.reply(True, 
                    self.protocol_version, 
                    frame.avps['assigned_tunnel_id'][1], 
                    frame.session_id, 
                    frame.control_sequence_id, 
                    frame.expected_control_sequence_id,
                    )
        self._ns_counter += 1
        
    def handle_cdn(self, frame):
        pass
    
    def shutdown(self):
        return    
