
from threading import Thread
import json
import pydivert
import Utils


class Filter(Thread):


    def __init__(self):
        Thread.__init__(self)
        self.__isFiltering=True


    def run(self):
        self.__isFiltering=True
        rules_table=self.get_rules()

        with pydivert.WinDivert() as w:
            for packet in w:

                packet_accepted = True

                for rule in rules_table['rules']:
                    protocols=[]
                    for id in packet.protocol:
                        protocols.append(Utils.resolve_protocol_ID[id])

                    if (packet.dst_port == Utils.safe_int(rule['port']) or rule['port'] == "*") and \
                            (packet.dst_addr == rule['ip_source'] or rule['ip_source'] == "*")and \
                            (rule['protocol'] in protocols or rule['protocol'] == "*"):
                        packet_accepted = False
                        break
                if packet_accepted:
                    try:
                        w.send(packet)
                    except OSError :
                        pass
                if not self.__isFiltering:
                    break

    def stop(self):
        self.__isFiltering = False

    def get_rules(self):
        with open("rules_table.txt", "r") as file:
            raw_data = file.read()
            return json.loads(raw_data)
