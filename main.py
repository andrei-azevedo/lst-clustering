import os
from scapy.all import *
from scapy.layers.inet import *

from sklearn.cluster import KMeans
from enum import Enum
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import struct

class PROTOCOL(Enum):
    TCP = 0
    UDP = 1

class LABEL(Enum):
    ETH_TRAFFIC = 0
    NORMAL_TRAFFIC = 1

def getPacketsFromPCAP(filepath):
    return PcapReader(filepath)

def processPCAPS(packets_with_tx, packets_without_tx):
    i = 0
    packet_list = []
    for packet in packets_with_tx:
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
    packet_list_without_tx = []
    for packet in packets_without_tx:
        try:
            if packet.haslayer(TCP):
                if len(packet[TCP].payload) > 0:
                    packet_list_without_tx.insert(i, (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, len(packet), bytes(packet[TCP].payload), PROTOCOL.TCP, LABEL.ETH_TRAFFIC))
                else:
                    packet_list_without_tx.insert(i, (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, len(packet), '', PROTOCOL.TCP, LABEL.ETH_TRAFFIC))
            elif packet.haslayer(UDP):                
                if len(packet[UDP].payload) > 0:
                    packet_list_without_tx.insert(i, (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport, len(packet), bytes(packet[UDP].payload), PROTOCOL.UDP, LABEL.ETH_TRAFFIC))
                else:
                    packet_list_without_tx.insert(i, (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport, len(packet), '', PROTOCOL.UDP, LABEL.ETH_TRAFFIC))
        except:
            pass

    X = np.array(packet_list)
    Y = np.array(packet_list_without_tx)
    #order by packet len to show histogram
    #X = X[X[:, 2].argsort()]
    df = pd.DataFrame(X)
    df2 = pd.DataFrame(Y)
    df[4] = df[4].astype(int)
    df2[4] = df2[4].astype(int)

    fig, ax = plt.subplots()
    #df.hist(column=4, ax=ax, color='g', alpha=1)
    #df2.hist(column=4, ax=ax, color='b', alpha=0.35)
    ax.hist(df[4], color='#908d8e', label=['With TX'])
    ax.hist(df2[4], color='#bdbabb', label=['Without TX'])
    plt.xlabel('Packet Size in Bytes')
    plt.ylabel('Number of Packets')
    plt.legend(loc='upper right')
    #plt.yscale('log')
    #plt.gca().get_xaxis().set_major_locator(ticker.MultipleLocator(100))
    plt.title('')
    plt.show()
    fig.savefig('fig.pdf')
    #df.to_csv('eth_without_tx.csv', index=False, header=False)
    
def main():
    packets_with_tx = getPacketsFromPCAP(os.path.join(os.getcwd(), 'file_with_tx.pcap'))
    packets_without_tx = getPacketsFromPCAP(os.path.join(os.getcwd(), 'file_without_tx.pcap'))
    processPCAPS(packets_with_tx, packets_without_tx)


if __name__ == '__main__':
    main()