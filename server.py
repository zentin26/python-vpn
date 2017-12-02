#!/usr/bin/python
import struct
import bitstruct
import time
import os
import signal
import sys
import src.frame
from src.l2tp import L2TPServer
from src.ipsec import IPsecServer
from src import log
from twisted.internet.task import LoopingCall
from twisted.internet import reactor, protocol
from src.utils import *


# initiate globals
logger = log.get_logger()


def main():
    def graceful_shutdown():
        # handle the shutdown procedure gracefully
        logger.info("Shutting down server")
        l2tp_server.shutdown()
        ipsec_server.shutdown()
        
    try:
        # initiate everything
        logger.info("Initiating server")
        config = load_config()
        l2tp_server = L2TPServer(**config['L2TP'])
        ipsec_server = IPsecServer(**config['IPsec'])

        # setup and run
        reactor.addSystemEventTrigger('before', 'shutdown', graceful_shutdown)
        reactor.listenUDP(config['L2TP']['port'], frame.FrameReciver(l2tp_server, frame.L2TPFrame))
        reactor.listenUDP(config['IPsec']['port'], frame.FrameReciver(ipsec_server, frame.IPsecFrame))
        reactor.run()


    except Exception as e:
        logger.critical(e, exc_info=True)

    finally:
        sys.exit()


if __name__ == '__main__':
    main()
