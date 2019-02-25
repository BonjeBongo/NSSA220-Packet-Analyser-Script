#MiniProj2 
#Evren Ince

# Function to filter ICMP packets from Node*.txt into text file Node*_filtered.txt
# only grabs icmp packets but no hex included

import sys

def read_packets(filename, L):
    # open file 
    hello = []
    f = open('Data/'+filename, 'r')
    data = f.read().split('\n\n')
    temp_ind = -1
    for i,line in enumerate(data):
        line = line.split()
        for word in line:   
            if 'ICMP' in word:
                temp_ind = i
            if 'unreachable' in word and i == temp_ind:
                temp_ind = -1    
        if i == temp_ind:        
            line = ''.join(elem for elem in data)
            hello.append(data[i:i+2])

    for line in hello:
        # line = line.split('\n')
        packet = ''.join(elem for elem in line)
        L.append(packet)
    
    # closes the file
    f.close()

def file_writer(filename1, packets):
    f1 = open('Data/'+filename1, 'w+')
    for packet in packets:
        f1.write(packet)
    f1.close()

def filter_packets():
    L = []
    for i in range(1,6):
        in_file = "Node" + str(i) + ".txt"
        out_file = "Node" + str(i) + "_filtered.txt"
        read_packets(in_file, L)
        file_writer(out_file, L)
        L = []

# Calls function
# filter_packets()
