import os
from scapy.all import *
from scapy.layers.inet import *

from sklearn.cluster import KMeans
from enum import Enum
import numpy as np
import pandas as pd
import struct

class PROTOCOL(Enum):
    TCP = 0
    UDP = 1

class LABEL(Enum):
    ETH_TRAFFIC = 0
    NORMAL_TRAFFIC = 1

def readPCAP(filepath):
    packets = PcapReader(filepath)
    i = 0
    packet_list = []
    for packet in packets:
        if packet.haslayer(TCP):
            if len(packet[TCP].payload) > 0:
                packet_list.insert(i, (packet[TCP].src, packet[TCP].dst, len(packet), bytes(packet[TCP].payload), PROTOCOL.TCP, LABEL.ETH_TRAFFIC))
            else:
                packet_list.insert(i, (packet[TCP].src, packet[TCP].dst, len(packet), '', PROTOCOL.TCP, LABEL.ETH_TRAFFIC))
        elif packet.haslayer(UDP):
            if len(packet[UDP].payload) > 0:
                packet_list.insert(i, (packet[UDP].src, packet[UDP].dst, len(packet), bytes(packet[UDP].payload), PROTOCOL.UDP, LABEL.ETH_TRAFFIC))
            else:
                packet_list.insert(i, (packet[UDP].src, packet[UDP].dst, len(packet), '', PROTOCOL.UDP, LABEL.ETH_TRAFFIC))

    X = np.array(packet_list)
    df = pd.DataFrame(X)
    df.to_csv('eth_traffic.csv', index=False, header=False)
    #filter rows of original data
    
def main():
    readPCAP(os.path.join(os.getcwd(), 'file_with_transactions.pcap'))


if __name__ == '__main__':
    main()