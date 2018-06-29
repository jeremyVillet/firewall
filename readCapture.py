print("Initializing supFirewall...")
from scapy.all import *
import json
import Utils


def filteringPcapFile(pcapFile):
    try:
     packets = rdpcap(pcapFile)
    except FileNotFoundError:
        print("ERROR : Can't found {0} file ".format(pcapFile))
        return

    denied_packet = 0

    with open("filtered.pcap", "w"): #creation fichier output
        pass
    with open("rules_table.txt", "r") as file:
        raw_data = file.read()
        rules_table= json.loads(raw_data)

    for packet in packets:
        ip,port="",""
        packet_accepted=True

        if IP in packet:
            ip=packet[IP].src

        if UDP in packet:
            port=packet[UDP].dport
        if TCP in packet:
            port = packet[TCP].dport

        for rule in rules_table['rules']:
            if (port == Utils.safe_int(rule['port']) or rule['port'] == "*") and \
                    (ip == rule['ip_source'] or rule['ip_source'] == "*") :
                packet_accepted=False
                denied_packet+=1
                break

        if packet_accepted:
            wrpcap('filtered.pcap', packet, append=True)
        else:
            print("#############################################################")
            print("packet deleted #{0} \n ip source : {1} \n port {2} ".format(denied_packet,ip,port))
            print("#############################################################")

    print("\n Finally , {0} packets have been deleted during the filtering.\n Result of the filering packet is available in the filtered.pcap file !\n".format(denied_packet) )


