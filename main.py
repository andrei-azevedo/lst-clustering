import os
from scapy.all import *
from scapy.layers.all import *

from sklearn.cluster import KMeans
import numpy as np
import matplotlib.pyplot as plt
import struct

def readPCAP(filepath):
    packets = PcapReader(filepath)
    i = 0
    packet_list = []
    for packet in packets:
        try:
            if packet.haslayer(TCP):
                if len(str(packet[TCP].payload)) > 0:
                    packet_list.insert(i, (0, len(packet), bytes(str(packet[TCP].payload)[0:18] + '\'', 'utf-8')))
                else:
                    packet_list.insert(i, (0, len(packet), '' * 16))
            elif packet.haslayer(UDP):
                if len(str(packet[UDP].payload)) > 0:
                    [t] = struct.unpack('f', bytes(str(packet[UDP].payload)[0:18] + '\'', 'utf-8'))
                    packet_list.insert(i, (0, len(packet), ))
                else:
                    packet_list.insert(i, (0, len(packet), '' * 16))
        except Exception as e:
            print(e)
            pass
        i += 1
        if i > 10000:
            break
    X = np.array(packet_list)
    kmeans = KMeans(n_clusters=3, random_state=0).fit(X)
    #filter rows of original data
    ax = plt.axes(projection ="3d")
    ax.scatter3D(X[:,1], X[:,0], X[:,2], color=kmeans.labels_.astype(float))
    ax.set_xlabel('X-axis', fontweight ='bold') 
    ax.set_ylabel('Y-axis', fontweight ='bold') 
    ax.set_zlabel('Z-axis', fontweight ='bold')
    plt.show()
    
def main():
    readPCAP(os.path.join(os.getcwd(), 'file.pcap'))


if __name__ == '__main__':
    main()