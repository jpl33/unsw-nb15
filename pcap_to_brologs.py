#!/usr/bin/env python

import os
import datetime
import subprocess
import shlex
import getpass
import sys
from subprocess import Popen, PIPE
from os import path
from pathlib import Path


#bro_data_dir = "/nsm/bro/logs"
bro_data_dir = "/nsm/bro/logs"
#pcap_dir = "/mnt/hgfs/cdx_2009/sandbox_win"
pcap_dir = "/mnt/hgfs/maccdc_2012/"

pcap=(".pcap",".dmp",".pcapng")

def is_pcap(file_name):	
	if file_name.endswith(pcap): 
		return True
	else:
		return False
def is__dir(parent, dir_name):
    if (not Path(parent+'/'+dir_name).is_dir() ):
         pp1=Path(parent+'/'+dir_name).mkdir()

		
def main():
	
	# Get list of directorys in bro data dir - aka already processed files
	
      print ("pcap files dir: %s" %bro_data_dir)	
      out_file= open('bro_processed_files.txt', 'r+') 
	
	# Get list of PCAP files to ready to be processed - if ctime of file is less than ctime of next file in file ring buffer
      print ("Pcap files dir %s" %pcap_dir)	
      pcap_file_list = os.listdir(pcap_dir)
      pcap_file_list.sort()
      print ("- files found %s" %pcap_file_list)
	
	# add to the to_be_removed array, pcap file entries that we do not want to process or other files in the folder that we do not want to process
      to_be_removed = []
      for f in pcap_file_list:
          if not( is_pcap(f)):
              to_be_removed.append(f)
              
      for l in out_file.readlines():
        l=l.split("\n")[0]
        to_be_removed.append(l)
        
      for f in to_be_removed:
            print ("Not pcap so not processing %s"%f)
            pcap_file_list.remove(f)
	
      num_pcap_files = len(pcap_file_list)
      pcap_file_dict = {}
      #for i in range(0,num_pcap_files):
		# if is_pcap(pcap_file_list[i]):j
			
			# # Get created time for this file and the next in the ring buffer
			# f1_created = datetime.datetime.fromtimestamp(os.path.getctime(pcap_dir + "/" + pcap_file_list[i]))
			# f2_created = datetime.datetime.fromtimestamp(os.path.getctime(pcap_dir + "/" + pcap_file_list[(i+1) % num_pcap_files]))
			
			# dirname = f1_created.isoformat() + "-" + pcap_file_list[i]
			
			# # Check to see if we've already processed this file and make sure that the ctime is less than the next in the ring buffer
			# if dirname in processed_files:
				# print "skipping since already processed %s"%dirname
				# continue

			# # uncomment the next lines if you are expecting more PCAP files to be generated in the pcap_dir directiry
			
			# #if f1_created < f2_created:
                  #pcap_file_dict[pcap_file_list[i]]
			# #else:
			# #	print "skipping due to time %s"%dirname
		# else:
			# print "more pcap check. skipping %f"%pcap_file_list[i]
		
	#print pcap_file_dict
      print ("NUMBER OF FILES TO PROCESS")
      print (len(pcap_file_list))
      
	# process files
      processed_files = list()
      #out_file= open('processed_files.txt', 'a') 
      for pf in range(0,num_pcap_files):
            f1=pcap_file_list[pf]
            print ("current file : %s" %f1)
		# for testing, only do first one
			
            output_dirname = f1.split(".")[0]

		# create the directory
            sdpwd="S3cur!ty"
            #s2=getpass.getpass(stream=sys.stderr)
            #cmd='mkdir %s/%s'%(pcap_dir,output_dirname)
            is__dir(pcap_dir,output_dirname)
            

            #os.makedirs(bro_data_dir + "/" + output_dirname)
            bro_cwd = pcap_dir + "/" + output_dirname
            bro_env = { "BROPATH": "/opt/bro/share/bro:/opt/bro/share/bro/site:/opt/bro/share/bro/policy:/opt/bro/share/securityonion"}
            bro_cmd = "/opt/bro/bin/bro -r %s/%s local.bro" %(pcap_dir, f1)
            bc=bro_cmd.split()
		
            print ("running bro on %s ..." % f1)
            run_bro = subprocess.Popen(['sudo', '-S']+bc, stdin=PIPE, stderr=PIPE, cwd=bro_cwd, env=bro_env,universal_newlines=True)
            sudo_prompt = run_bro.communicate(sdpwd + '\n')[1]            
            run_bro.wait()
            bro_file_list = os.listdir(bro_cwd)
            #f2s=f2.split(".")
            #dt_cmd="cat $s | bro-cut -c -D %m/%d/%Y-%H:%M:%S >$s"%(f2,(f2s[0]+'_dt.'+f2s[1]))
            f1+= ("\n")
            out_file.write(f1)
            out_file.flush()
            
            
      

			
		
	
	
	
	
	
main()
