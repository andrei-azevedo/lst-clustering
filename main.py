import os
from scapy.all import *
from scapy.layers.all import *

from sklearn.cluster import KMeans
import numpy as np
import matplotlib.pyplot as plt

def readPCAP(filepath):
    packets = PcapReader(filepath)
    i = 0
    packet_list = []
    for packet in packets:
        try:
            if packet.haslayer(TCP):
                packet_list.insert(i,(1, len(packet)))
            elif packet.haslayer(UDP):
                packet_list.insert(i, (0, len(packet)))
        except:
            pass
        i += 1
    X = np.array(packet_list)
    kmeans = KMeans(n_clusters=3, random_state=0).fit(X)
    #filter rows of original data
    plt.scatter(X[:,1], X[:,0], c=kmeans.labels_.astype(float))
    plt.xlabel('Protocol')
    plt.ylabel('Size')
    plt.show()
    
def main():
    readPCAP(os.path.join(os.getcwd(), 'file.pcap'))


if __name__ == '__main__':
    main()