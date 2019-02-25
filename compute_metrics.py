"""
@Author Jack Hyland
@Date 12/11/2018
"""


'''
Take in a list of dictionaries;
each dictionary will be composed of a
src - source IP
seqN - Sequence length
dst - destination
time - time
repS - Echo reply sent
repR - Echo reply received
reqR - Echo request received
reqS - Echo request sent
TTL - time to live
dataB - the amount of bytes for data
totalB - the amount of bytes total
'''

def compute(packets, NodeNumber):
    noOutput = 0

    Echo_Request_Bytes_Sent = 0
    Echo_Request_Bytes_Received = 0
    Echo_Request_Data_Sent = 0
    Echo_Request_Data_Received = 0

    Amount_Of_Echo_Requests = 0
    Sum_Hop_Count = 0

    for packet in packets:
        if packet['reqS'] == 1:
            Echo_Request_Bytes_Sent += packet['totalB']
            Echo_Request_Data_Sent += packet['dataB']
            Amount_Of_Echo_Requests += 1
            Sum_Hop_Count += (packet['TTL'] + 1)
        elif packet['reqR'] == 1:
            Echo_Request_Bytes_Received += packet['totalB']
            Echo_Request_Data_Received += packet['dataB']
            Sum_Hop_Count += (packet['TTL'] + 1)
            Amount_Of_Echo_Requests += 1
        elif packet['repR'] == 1:
            Sum_Hop_Count += (packet['TTL'] + 1)
            Amount_Of_Echo_Requests += 1

    # Data metrics
    repS = 0
    repR = 0
    reqR = 0
    reqS = 0 # number of requests sent
    Sum_Round_Trip_Time = 0  # RTT
    Sum_Reply_Delay = 0  # microseconds
    Sum_All_Ping_RTT = 0

    Number_Of_Sequences = 0 # used for RTT calculation
    Number_Of_Replys = 0

    sequenceNum = {}
    replyDelay = {}

    for packet in packets: #  Iterates through the list of dictionaries
        if packet['seqN'] not in sequenceNum: # if we haven't previously seen this sequence add it
            sequenceNum[packet['seqN']] = packet
        else: #  we have seen this sequence before
            previousPacket = sequenceNum[packet['seqN']]
            Sum_All_Ping_RTT += (packet['time'] - previousPacket['time'])
            if previousPacket['reqS'] == 1 and packet['repR'] == 1:
                Sum_Round_Trip_Time += (packet['time'] - previousPacket['time']) * 1000
                Number_Of_Sequences += 1
            del sequenceNum[packet['seqN']]

        if packet['reqR'] == 1 and packet['seqN'] not in replyDelay:
            replyDelay[packet['seqN']] = packet
        elif packet['repS'] == 1 and packet['seqN'] in replyDelay:
            previousPacket = replyDelay[packet['seqN']]
            Sum_Reply_Delay += (packet['time'] - previousPacket['time']) * 1000000
            Number_Of_Replys += 1
            del replyDelay[packet['seqN']]

    accumulator = 0
    num = 0
    for packet in packets:
        # collecting totals
        if packet['repS'] == 1:
            repS += 1
        elif packet['repR'] == 1:
            repR += 1
            num += 1
            accumulator += packet['TTL'] + 1
        elif packet['reqR'] == 1:
            reqR += 1
        elif packet['reqS'] == 1:
            reqS += 1

    if Sum_Round_Trip_Time == 0:
        Echo_Request_Throughput = 'N/A'
        Echo_Request_Goodput = 'N/A'
        noOutput = 1
    else:
        Echo_Request_Throughput = Echo_Request_Bytes_Sent/Sum_Round_Trip_Time
        Echo_Request_Goodput = Echo_Request_Data_Sent / Sum_Round_Trip_Time

    if Number_Of_Sequences == 0:
        RTT = 'N/A'
        noOutput = 1
    else:
        RTT = Sum_Round_Trip_Time / Number_Of_Sequences

    if Number_Of_Replys == 0:
        Average_Reply_Delay = 'N/A'
        noOutput = 1
    else:
        Average_Reply_Delay = Sum_Reply_Delay / Number_Of_Replys

    AVG_Hop_Count = float(accumulator) / num

    if noOutput == 0:
        fp = open("MiniProject2Output.csv", 'a')
        fp.write('Node ' + str(NodeNumber) + '\n')
        fp.write('\n')
        fp.write('Echo Requests Sent,Echo Requests Received,Echo Replies Sent,Echo Replies Received' + '\n')
        fp.write(str(reqS) + ',' + str(reqR) + ',' + str(repS) + ',' + str(repR) + '\n')
        fp.write('Echo Request Bytes Sent (bytes),Echo Request Data Sent (bytes)' + '\n')
        fp.write(str(Echo_Request_Bytes_Sent) + ',' +  str(Echo_Request_Data_Sent) + '\n')
        fp.write('Echo Request Bytes Received (bytes),Echo Request Data Received (bytes)' + '\n')
        fp.write(str(Echo_Request_Bytes_Received) + ',' +  str(Echo_Request_Data_Received) + '\n')
        fp.write('\n')
        fp.write('Average RTT (milliseconds),' + str(RTT) + '\n')
        fp.write('Echo Request Throughput (kB/sec),' + str(Echo_Request_Throughput) + '\n')
        fp.write('Echo Request Goodput (kB/sec),' + str(Echo_Request_Goodput) + '\n')
        fp.write('Average Reply Delay (microseconds),' + str(Average_Reply_Delay) + '\n')
        fp.write('Average Echo Request Hop Count,' + str(AVG_Hop_Count) + '\n' + '\n')
        fp.close()