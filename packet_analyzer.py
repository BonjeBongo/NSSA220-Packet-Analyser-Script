from filter_packets import *
from packet_parser import *
from compute_metrics import *

#main loop
filter_packets()
for num in range(1, 6): #  goes through 1 - 5
    compute(parse("Node" + str(num) + "_filtered.txt"), num)
    print("Node" + str(num) + " done!")

