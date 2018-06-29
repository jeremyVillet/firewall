import pydivert
from Utils import *


with pydivert.WinDivert() as w:
    for packet in w:
        test= True
        if packet.dst_port==443:
            print('\npacket: ',packet.src_addr)
            print('\n',packet.dst_addr)
            for s in packet.protocol:
                print("Protocol " ,resolve_protocol_ID[s])
            if packet.dst_addr=="10.10.18.137":
                test=False
                print("denied")
            if test :
                try:
                 w.send(packet)
                except:
                    pass



