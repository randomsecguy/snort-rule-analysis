#!/usr/bin/env python
import os
import time
import matplotlib.pyplot as plt

# This script reads all the files in the folder specified, counts tcp rules and writes them to a new file 
os.system('clear')


def createpie(tcp, udp):
 # make a square figure and axes
 plt.figure(1, figsize=(8.5,8.5))
 ax = plt.axes([0.1, 0.1, 0.8, 0.8])


 
 # The slices will be ordered and plotted counter-clockwise.
 labels = 'TCP', 'UDP', 'Other'
 
 other = 100 - (tcp + udp)
 
 fracs = [tcp, udp, other]
 #explode=(0, 0.05, 0, 0)

 plt.pie(fracs, labels=labels, autopct='%1.1f%%', shadow=True, startangle=90)
                # The default startangle is 0, which would start
                # the Frogs slice on the x-axis.  With startangle=90,
                # everything is rotated counter-clockwise by 90 degrees,
                # so the plotting starts on the positive y-axis.

 plt.title('Distribution of Snort Rules')

 plt.show()


#def createbar(total, tcp, udp):
 
def sketchplot(tcp, udp):

 with plt.xkcd():
      
    fig = plt.figure()
    ax = fig.add_axes((0.1, 0.2, 0.8, 0.7))
    ax.bar([-0.125, 1.0-0.125], [0, 100], 0.25)
    ax.spines['right'].set_color('none')
    ax.spines['top'].set_color('none')
    ax.xaxis.set_ticks_position('bottom')
    ax.set_xticks([0, 1])
    ax.set_xlim([-0.5, 1.5])
    ax.set_ylim([0, 110])
    ax.set_xticklabels(['TCP', 'UDP'])
    plt.yticks([])

    plt.title("DISTRIBUTION OF SNORT RULES")

    
 plt.show()










def listdir_nohidden(path):               #Return only those entries in the directory which are not hidden and dont contain ~
    for f in os.listdir(path):            # listdir() returns a list containing the names of the entries in the directory given by path
        if 'rules' in f and not f.startswith('.') and not '~' in f:
            yield f

def collect_stats():
 print "\n"
 countt = 0
 countcp = 0
 countfiles = 0
 countexp = 0

 path = '/home/zafzal/Desktop/snortrules-snapshot-2970/rules'  
 #path = '/home/zafzal/Desktop/snort_2.4.0/rules'

 for dir_entry in listdir_nohidden(path):                          #dir_entry will simply have names of every file at that path
  dir_entry_path = os.path.join(path, dir_entry)
  if os.path.isfile(dir_entry_path):
   countfiles = countfiles + 1
   my_file = open(dir_entry_path)
   data = my_file.read()

   
   print "File","[",countfiles,"]:" , dir_entry, "|Total Rules:", data.count("-> ") , "| TCP Rules:", data.count("alert tcp")   #count() returns count of how many times obj occurs in list
   countt = countt + data.count(" -> ") + data.count(" <> ") + data.count(" <- ")
   countcp = countcp + data.count("alert tcp")

 print "\n"
 print "-----------ANALYSIS COMPLETE--------------------" 
 print "Folder                   :", path 
 print "Total execution time     :", time.time() - start_time,"seconds"
 print "Number of files in folder:", countfiles
 print "Total number of rules    :", countt
 print "No. of TCP related rules :", countcp, "| Percentage:",100 * float(countcp)/float(countt)
 print "------------------------------------------------"
 print "\n"

#---------------------------------------------------------------------------------------------------------------------#



def collect_stats2():
 #print "Analysis using method2" 

 countcp2 = 0
 countcon = 0
 countis  = 0
 countoff = 0
 counttt2 = 0
 countfiles2 = 0
 countudp = 0
 countcp3 = 0
 count_untestable = 0
 
 path = '/home/zafzal/Desktop/snortrules-snapshot-2970/rules'  
 #path = '/home/zafzal/Desktop/snort_2.4.0/rules'


 try:                                                           #try to delete the old file
  os.remove('tcp.rules')
 except:
  pass


 for dir_entry in listdir_nohidden(path):                          #dir_entry will simply have names of every file at that path
  dir_entry_path = os.path.join(path, dir_entry)
  if os.path.isfile(dir_entry_path):
   
   countfiles2 = countfiles2 + 1
   print dir_entry   
  
   my_file = open(dir_entry_path, "r")
   tcp_file =open('tcp.rules', "a")
   #lines_to_check_for = [ line for line in file(dir_entry_path, "r") ]
   for line in my_file:
    
    if "->" in line or "<-" in line or "<>" in line  :       #Its a rule
     counttt2 = counttt2 + 1 
     if "alert tcp" in line:
      countcp2 = countcp2 + 1

      if "offset" in line:
       countoff = countoff + 1
  
      if "content:" in line:                                 #Its a testable tcp rule with content attribute
       countcon = countcon + 1
       
      if "metadata:" in line:
       countis = countis + 1
      
     # if "content:" not in line or "pcre:" in line or "byte_test:" in line or "byte_jump:" in line or "byte_extract:" in line or "detection_filter:" in line or "modbus_data:" in line or "modbus_func:" in line or "sip_"  in line:
      # count_untestable = count_untestable + 1
      
      
      if "content:" in line and "pcre:" not in line and "byte_test:" not in line and "byte_jump:" not in line and "detection_filter:" not in line and "modbus_data:" not in line and "modbus_func:" not in line and "byte_extract:" not in line and "sip_" not in line:       #Its a tcp rule which we can test
       countcp3 = countcp3 + 1
       tcp_file.write(line)
       #tcp_file.write('\n')
       
              
    # elif "alert udp" in line:
     # countudp = countudp + 1
     
     

   tcp_file.close()



 print "------------------------------------------------"
 print "Checked files:", countfiles2
 print "Total number of rules               :", counttt2
 print "Number of TCP related rules         :", countcp2,       "| Percentage:", 100 * float(countcp2)/float(counttt2)
 print "Number of UDP related rules         :", countudp,       " | Percentage:", 100 * float(countudp)/float(counttt2)
 print "\n"
 
 print "TCP Rules using content attribute   :", countcon,  "| Percentage:", 100 * float(countcon)/float(countcp2)
 print "TCP Rules using offset attribute    :", countoff,  " | Percentage:", 100 * float(countoff)/float(countcp2)
 print "\n"

 print "No. of testable TCP related rules     :", countcp3,       "| Percentage:", 100 * float(countcp3)/float(countcp2) , "(written to tcp.rules)"
 print "No. of untestable tcp related rules   :", count_untestable,  "| Percentage:", 100 * float(count_untestable)/float(countcp2)

 print "------------------------------------------------"
 print "\n"


 
 tcp = 100 * float(countcp2)/float(counttt2)
 udp = 100 * float(countudp)/float(counttt2)
 createpie(tcp, udp)
 #sketchplot(countcp2, countudp)
 

 return "True"





#count_total("app-detect.rules")
#count_string_occurance("app-detect.rules")
#start_time = time.time()
#collect_stats()

#collect_stats2()
#print "Total execution time     :", time.time() - start_time,"seconds"




