#!/usr/bin/env python2
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from tests.mptcptestlib import *
from _random import Random
from Crypto.Random.random import shuffle
import binascii
from decimal import *
import string

"""Fragment an HTTP request over multiple MPTCP flows to demonstrate the potential for trivial IDS evasion.

No params or -h for help.

Example usage:
# python myids.py -n 5 --file payload.txt 192.168.249.128 --port 6004
# python myids.py -n 2 --file payload.txt 192.168.249.128 --port 6004 -data_sublow 2

Default number of flows is 5, and the request is split evenly over all flows.

"""

#TODO: Add port randomisation (with availability checking)
#TODO: Speed up opening flows (faster polling - or an option to set delay?)
def core(target, tgt_port, src_ip, nsubflows, first_src_port, payloadFile, randomSrcPorts, datasubflow):
    
    global count
    count = 1
    conf = {"printanswer":False, "debug":1, "check": False}
    t = ProtoTester(conf)
    s = MPTCPState()
    m = MPTCPTest(tester=t, initstate=s)
    timeout = .3
    fileBufferSize = 5000  

    if not randomSrcPorts:
        print "Ports are not random with first:", first_src_port
        ports = range(first_src_port, first_src_port + nsubflows)
    else:
        print "Ports are random with first:", first_src_port
        ports = [random.randrange(1,65534) for i in range(nsubflows)]
     
    t.toggleKernelHandling(src_ip, enable=False)                   #Stop kernel from handling packets 
    try:
        #TODO:s abstract this into a function
        firstSubflow = True
        for port in ports:
            #print "Opening MPTCP connection from port", port
            if firstSubflow:                                       #No previous subflow exists, so start a new mptcp connection
                print "Opening MPTCP connection & 1st flow from port", port                                    
                conn_open = [m.CapSYN, m.Wait, m.CapACK]           #Craft/generate 1st packet of the MPTCP 3-way connection handshake (MP_CAPABLE handshake) 
                                                                   #+ wait for reply (i.e SYN/ACK) + Craft 3rd packet of the handshake
                firstSubflow=False
            
            else:                                                  #If a connection already exists  
                count = count + 1
                print "Opening new subflow from port", port , "to port", tgt_port                                     
                conn_open = [m.JoinSYN, m.Wait, m.JoinACK]         #Craft first packet of the MP_JOIN handshake + wait for reply + craft 3rd packet of MP_JOIN handshake
            sub = s.registerNewSubflow(dst=target, src=src_ip, dport=tgt_port, sport=port)  #Create and register the subflow to make sure it doesnt already exist
            t.sendSequence(conn_open, initstate=s, sub=sub, waitAck=True,timeout=timeout)  #Send the above crafted/generated packets

        
        if payloadFile:
         f = open(payloadFile)

      
        if not datasubflow:
         print "No subflow preference stated,   " , "Splitting payload across", len(ports), "subflows"
         for data in read_file_chunks(f, fileBufferSize):
          
          tosendhex = []
          tosendstr = []
          #data = '\xFF\xFF\xFF\xFF\xFF\xFF'  
              
          #data = data.split("\n")      #split the input into two at the new line character. first part is what we require
          
          if "|" in data:                           #Payload data has binary data indicated by pipe '|' 
           print "Payload in file: ", data
           data = data.split('|')     #remove the white space from the string and then split it using | as a separator returning a list
           
           #print "Data after split", data
           for x in data:                                        #loop over the resulting list after split
            
            if all(c in string.hexdigits for c in x.replace(' ','')): 
             tosendhex.append(x)
             #print x , "is hex"    
            else:          
             tosendstr.append(x)
             #print x, "is not hex"
           
           hexdata = ''.join(tosendhex)
           hexdata = hexdata.split("\n")
           #print "Hex list has", hexdata[0]         #coz hexdata[1] has new line character

           strdata = ''.join(tosendstr)              #convert the list to a string
           strdata = strdata.split("\n")
           #print "String list has", strdata[0]

 
           if tosendstr:               #the payload is mixed e.g |5C|x0c|5C|x0c|5C|x0c|5C|x0c|5C|x0c|5C|x0c|5C|x0c|5C|x0c
            #print "Payload is mixed, this func hasnt been implemented yet"
            #sys.exit(1)
                           
            #Write code to handle this situation. One solution could be to create many subflows (equal to length of both lists combined).Then we send data one item at a time. e.g we send 5C as hex on
             #subflow1, then we send x0c as str on subflow2 and so on.
            print "MIXED PAYLOAD with length of", len(data)

            #nsubflows = len(data)  Need to set number of subflows equal to data length because we will have one subflow for each character of payload. Problem: subflows have already been established

            for y in data:
             if all(c in string.hexdigits for c in y.replace(' ','')): 
              
              #if y is not '':
              print y , "is hex"           
              
              y = y.split("\n")              
             
              if not Checklength(y[0].replace(" ","")):      #Remove spaces and then check if given hex is odd e.g | C| -> |C| is odd. C cant be hex so we will treat it as a string. 
               print y[0], "is Odd length"
               #y = y[0].ljust(len(y[0]) + 1, '0')            #Padd it to C0
               #print "Padded to", y
               print "Sending",y[0], "as string because hex cant be single value"
               snt = m.send_data_sub(s=s, data=y[0], sub=s.sub[0], waitAck= True, raw=False)
               continue               
  
              y = ''.join(y)                                 #convert to string
              data = binascii.unhexlify(y.replace(" ",""))   #unhexlify
              print "After unhexlify:", data
              data = binascii.hexlify(data).upper()
              snt = m.send_data_sub(s=s, data=data, sub=s.sub[0], waitAck= True, raw=True)
              #snt = m.send_data(s=s, data=data, waitAck=True, timeout=timeout, raw=True)

             else:    
              
              print y, "is not hex"
              snt = m.send_data_sub(s=s, data=y, sub=s.sub[0], waitAck= True, raw=False)
              #snt = m.send_data(s=s, data=data, waitAck=True, timeout=timeout, raw=False)
            




           if not tosendstr:          #if tosendstr list is empty. Means all the data in payload is hex. No mixed payload
            print "Payload is purely HEX" 
            data = binascii.unhexlify(hexdata[0].replace(" ",""))           
            print "Payload to send as raw hex from myids: ", data
            print "-------------------------------------------------------------------------------"
            snt = m.send_data(s=s, data=data, waitAck=True, timeout=timeout, raw=True) #Send the data using all possible subflows, also divides data equally among all subflows
        
          else:                   #No pipe in payload, looks like its string
           print "Payload to send as str from myids: ", data
           print "-------------------------------------------------------------------------------"
           #data = binascii.unhexlify(data)  
           snt = m.send_data(s=s, data=data, waitAck=True, timeout=timeout, raw=True) #Send the data using all possible subflows, also divides data equally among all subflows 
           
           




        else:
         if datasubflow <= len(ports):
          for data in read_file_chunks(f, fileBufferSize):
           print "Length of s.sub is", len(s.sub)
           print "*********Data to be sent on\n", s.sub[datasubflow - 1], "******************\n",
           #data = Raw('\xFF\xFF\xFF\xFF\xFF\xFF')
           #print data
           snt = m.send_data_sub(s=s, data=data, sub=s.sub[datasubflow - 1], waitAck= True)
         else:
          print "Error: Data subflow can not be greater than total num of subflows"
          sys.exit(1)



        #This acks data on every subflow 20 times
        #TODO: Abstract this into a function
        #for i in range(1, 5):
        #    j = 0
        #    for sflow in s.sub:
        #        #print "Subflow ", j, " cycling..."
        #        ackDss=[m.DSSACK]
        #        t.sendSequence(ackDss, initstate=s, sub=sflow,waitAck=True, timeout=timeout)
        #        j += 1
            #print " ------- Heartbeat Number", str(i)

        j = 0
        for sflow in s.sub:
            data_fin = [m.DSSFIN]#, m.DSSACK]       #Craft DataFIN packet + Craft DSSACK packet (need to read more on DSS)
            t.sendSequence(data_fin, initstate=s, sub=sflow, waitAck=True, timeout=timeout) #Send the above crafted/generated packets
            print "Subflow", j, "closed FIN"
            j += 1

    except PktWaitTimeOutException:
        print("Waiting has timed out, test exiting with failure")
        sys.exit(1)
    except IOError:
        print("IO Error Occured - Does file exist?")
    finally:
        t.toggleKernelHandling(src_ip, enable=True) # or manually with iptables -X  && iptables -F   #Allow kernel to handle packets again


def read_file_chunks(fileObj, chunkSize):
    while True:
        data = fileObj.read(chunkSize).splitlines()          #splitlines will split new lines
        if not data:
            break
        yield data[0]



def get_local_ip_address(target):
    """Return the the IP address suitable for the target (ip or host)

    This appears to be the best cross platform approach using only
    the standard lib. Better ideas welcome.
    """
    #TODO: handle err if no suitable IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((str(target), 8000))
    ipaddr = s.getsockname()[0]
    s.close()
    return ipaddr


def parse_args():
    import argparse
    import itertools
    import sys

    parser = argparse.ArgumentParser(description='Fragment an HTTP request over multiple MPTCP flows.')
    parser.add_argument("--ip", action="store", dest="src_ip", help="use the specified source IP for all traffic")
    parser.add_argument('target', action="store", help=' Target IP')
    parser.add_argument('-p', '--port', action="store", type=int, help='target port', default=80)
    parser.add_argument("-n", '--nsubflows', action="store", type=int, help='Number of subflows to create', default=5)
    parser.add_argument('--first_src_port', action="store", type=int, help='First of nsubflows src ports', default=49152)
    parser.add_argument('--file', action="store", help='File to send instead of a payload', default=None)
    parser.add_argument('--random_src_ports', action="store", help='use random ports', default=False)
    parser.add_argument('--data_subflow', action="store", type=int, help='Choose the subfow to send all data on', default=0)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    args.src_ip = args.src_ip if args.src_ip else get_local_ip_address(args.target)
    return args.target, args.port, args.src_ip, args.nsubflows, args.first_src_port, args.file, args.random_src_ports, args.data_subflow





###################################MAIN######################################

#target, port, src_ip, nsubflows, first_src_port, payloadFile, randomSrcPorts, datasubflow = parse_args()

#core(target, port, src_ip, nsubflows, first_src_port, payloadFile, randomSrcPorts, datasubflow)
# vim: set ts=4 sts=4 sw=4 et:












