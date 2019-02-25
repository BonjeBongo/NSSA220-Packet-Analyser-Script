#MiniProj2 
#Team 7 - Evren, Sem, Jack
# Parser - Sem
# Obj:
#	 Get the data from file as a list of dictionaries
# Secondary obj:
#	 Use Hex


# REQUIRED DATA
# 1. Number of Echo Requests sent
# 2. Number of Echo Requests received
# 3. Number of Echo Replies sent
# 4. Number of Echo Replies received

# 5. Total Echo Request bytes sent
#    In bytes, based on the size of the "frame"
# 6. Total Echo Request bytes received
#    In bytes, based on the size of the "frame"

# 7. Total Echo Request data sent
#    In bytes, based on amount of data in the ICMP payload
# 8. Total Echo Request data received
#    In bytes, based on amount of data in the ICMP payload

# Time Based Metrics
# 1. Average Ping Round Trip Time (RTT)
#    Ping RTT is defined as the time between sending an Echo Request packet and receiving a corresponding Echo Reply packet from the destination Measured in milliseconds

# 2. Echo Request Througput (in kB/sec)
#    Defined as the sum of the frame sizes of all Echo Request packets sent by the node divided by the sum of all Ping RTTs

# 3. Echo Request Goodput (in kB/sec)
#    Defined as the sum of the ICMP payload

# 4. Average Reply Delay (in microseconds)
#    Defined as the time between the destination node receiving an Echo Request packet and sending an Echo Reply packet back to the source

# Average number of hops per Echo Request
#    The hop count of an Echo Request is defined as the number of networks that an Echo Request packet must traverse in order to reach its destination
#    Hop count will be 1 if the destination is on a node's network or 3 if it has to go through routers to reach its destination
#    You cannot hard code this logic since it's not accurate for any given network, just this topology. (Hint: think about Node 5 or a field in the IP header)

#TL:DR:
# 1 Num of and 2 Byte count of Sent request
# 1 Num of and 2 Byte count of Recieved request
# 1 Num of Sent reply
# Num of Recieved reply

#http://academy.delmar.edu/Courses/ITSY2430/Handouts/PingPacketDecoded.html

'''
    metric output
    Echo Requests Sent:num
    Echo Requests Received:num

    Echo Replies Sent:num
    Echo Replies Received:num
    
    Echo Request Bytes Sent (bytes):num
    Echo Request Data Sent (bytes):num

    Echo Request Bytes Received (bytes):num
    Echo Request Data Received (bytes):num
                
    Average RTT (milliseconds):num

    max packet length w iphead = 65,535
    max data length = 65,507
    ethhead (14) + iphead (20) + ICMPhead (8) + data (36-65507)

    Echo Request Throughput (kB/sec):num 
    Echo Request Goodput (kB/sec):num

    Average Reply Delay (microseconds):num

    Average Echo Request Hop Count:num


   packet_data= 
    [
        {src:192.xxx.xxx, dest:192.xxx.xxx, seqN:14, reqS:1, reqR:0, repS:0, repR:0, ttl:1-128, totalB:packet length in bytes, dataB:data length in bytes, time:0.00000},
        {src:192.xxx.xxx, dest:192.xxx.xxx, seqN:14, reqS:0, reqR:1, repS:0, repR:0, ttl:1-128, totalB:packet length in bytes, dataB:data length in bytes, time:0.00000},
        {src:192.xxx.xxx, dest:192.xxx.xxx, seqN:14, reqS:0, reqR:0, repS:0, repR:1, ttl:1-128, totalB:packet length in bytes, dataB:data length in bytes, time:0.00000},
        {src:192.xxx.xxx, dest:192.xxx.xxx, seqN:14, reqS:0, reqR:0, repS:1, repR:0, ttl:1-128, totalB:packet length in bytes, dataB:data length in bytes, time:0.00000},
    ]

'''

#http://academy.delmar.edu/Courses/ITSY2430/Handouts/PingPacketDecoded.html

import re

def read_file(FILENAME):
    meta = []

    #Compile case insensitive hex regex to find hex data only, positive look ahead using group(1)
    # hexReg = r'(([a-f0-9]{2} ){2})'
    hexReg = r'(?<!\w)([a-zA-Z\d]{2} ){2,}'
    getHex = re.compile(hexReg, re.IGNORECASE)

    #compile regex to grab the time from wireshark pre-parsed data
    timeReg = r'\d*\.\d{6}'
    getTime = re.compile(timeReg)

    with open(FILENAME,'r') as readFile:
        data = readFile.read() #read in all data

        packetDump = getHex.finditer(data) #create an itterable from parsed regex
        hexOnly = []
        for item in packetDump:
            hexOnly.extend(item.group(0).split()) #split group 0 (0-16 bytes) and store them in an array

        # print(hexOnly) #DEBUG

        packetDump = []
        while len(hexOnly)>0:
            length = int(hexOnly[16]+hexOnly[17], 16) + 14 #calculate packet length
            packetDump.append(hexOnly[:length]) #make a copy of that packet as a byte list
            del(hexOnly[:length]) #delete packet from hex

        timeMeta = []
        timeMeta.extend(float(time) for time in getTime.findall(data)) #parse for time with regex and cast as float

    return timeMeta, packetDump

def parse(FILENAME):

    timeMeta, packetDump = read_file(FILENAME)

    #bit indexi
    IPHeadLength = 14
    IPLengthStart = 16
    IPLengthEnd = 17
    TTL = 22
    checksumStart = 24
    checksumEnd = 25
    srcStart = 26
    srcEnd = 30
    dstStart = 30
    dstEnd = 34
    echoType = 34
    seqStart = 40
    seqEnd = 41
    dataStart = 42

    nodeMeta = []
    packetMeta = {}
    for i,packet in enumerate(packetDump):

        packetMeta["seqN"] = int(packet[seqStart]+packet[seqEnd], 16) #Packet Sequence

        packetMeta["src"] = ".".join(str(int(byte,16)) for byte in packet[srcStart:srcEnd]) #Source IP
        packetMeta["dst"] = ".".join(str(int(byte,16)) for byte in packet[dstStart:dstEnd]) #Destination IP

        packetMeta["reqS"] = 0 #Echo Request (08) Sent (1 if 08 && !chksm)
        packetMeta["reqR"] = 0 #Echo Request (08) Received (1 if 08 && chksm)
        packetMeta["repS"] = 0 #Echo Reply (00) Sent (1 if 00 && !chksm)
        packetMeta["repR"] = 0 #Echo Reply (00) Received (1 if 00 && chksm)

        checksum = int(packet[checksumStart]+packet[checksumEnd], 16) #Header Checksum
        ICMPtype = int(packet[echoType],16) #08 Echo Request | 00 Echo Reply

        if (checksum == 0 and ICMPtype == 8):
            packetMeta["reqS"] = 1
        if (checksum != 0 and ICMPtype == 8):
            packetMeta["reqR"] = 1
        if (checksum == 0 and ICMPtype == 0):
            packetMeta["repS"] = 1
        if (checksum != 0 and ICMPtype == 0):
            packetMeta["repR"] = 1

        packetMeta["TTL"] = 128 - int(packet[TTL],16) #Packet Hop Counts

        packetMeta["totalB"] = len(packet) #Byte count for whole packet
        packetMeta["dataB"] = len(packet[dataStart:]) #Byte count for data only

        packetMeta["time"] = timeMeta[i] #Time of packet arival
        nodeMeta.append(packetMeta) #Append to main list
        packetMeta = {} #Clear Dictionary

    # print(nodeMeta)
    return(nodeMeta)

# parse()