#!/usr/bin/env python
import os
import re

#This script should read the tcp rules file and parse it. It should extract the dest port and content of each rule and return them

# alert tcp $EXTERNAL_NET $FILE_DATA_PORTS -> $HOME_NET 123 (msg:"INDICATOR-SHELLCODE unescape encoded shellcode"; flow:to_client,established; content:"unescape"; content:"spray"; fast_pattern:only; pcre:"/unescape\s*\x28\s*[\x22\x27]\x25[0-9a-f]{2}([\x22\x27]\s*\x2B\s*[\x22\x27])?\x25[0-9a-f]{2}/smi"; metadata:service ftp-data, service http, service imap, service pop3; classtype:shellcode-detect; sid:26791; rev:2;)


global p, con


def printfun(content,port):

 for item in content:
  print "content:",  item
  
 if port[0]:
  print "Port is", port[0]
 else:
  print "Port is", "any"
 print "\n"




def tcp_parse(line):

 #f1 = open('temp.rules', "r")

 #for line in f1:  
  #content = re.findall('(?:content):"(\S+)"', line)
  content = re.findall('(?<=content:")([^"]+)', line)
  port = re.search('(\d*)\s*\(', line)
  
  if port and content:
   if port.group(1):
    return content, port.group(1)
   else:
    port = "any"
    return content, port






#tcp_parse()



