import os
from scapy.all import *
from scapy.layers.inet import *

from sklearn.cluster import KMeans
from enum import Enum
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
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
        try:
            if packet.haslayer(TCP):
                if len(packet[TCP].payload) > 0:
                    packet_list.insert(i, (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, len(packet), bytes(packet[TCP].payload), PROTOCOL.TCP, LABEL.ETH_TRAFFIC))
                else:
                    packet_list.insert(i, (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, len(packet), '', PROTOCOL.TCP, LABEL.ETH_TRAFFIC))
            elif packet.haslayer(UDP):                
                if len(packet[UDP].payload) > 0:
                    packet_list.insert(i, (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport, len(packet), bytes(packet[UDP].payload), PROTOCOL.UDP, LABEL.ETH_TRAFFIC))
                else:
                    packet_list.insert(i, (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport, len(packet), '', PROTOCOL.UDP, LABEL.ETH_TRAFFIC))
        except:
            pass

    X = np.array(packet_list)
    #order by packet len to show histogram
    #X = X[X[:, 2].argsort()]
    df = pd.DataFrame(X)
    df[4] = df[4].astype(int)
    df.hist(column=4)
    plt.show()
    #df.to_csv('eth_without_tx.csv', index=False, header=False)
    
def main():
    readPCAP(os.path.join(os.getcwd(), 'file_with_tx.pcap'))


if __name__ == '__main__':
    main()