#!/usr/bin/env python

import os
import datetime
import subprocess
import sys
import pathlib
import pathlib
import glob

from subprocess import Popen, PIPE
from os import path
from pathlib import Path
import logging



pcap_dir = "/mnt/hgfs/maccdc_2012"
pcap=(".pcap",".dmp",",pcapng")

def is_pcap(file_name):
    """simple function, user modifiable, to determine if a given file is in fact a PCAP file we want to process
    Currently just uses the naming convention"""
    
    if file_name.endswith(pcap):
        return True
    else:
        return False

def is__dir(parent, dir_name):
    if (not Path(dir_name).is_dir() ):
         pp1=Path(parent+'/'+dir_name).mkdir()

        
        
def main():
    
    
    # Get list of PCAP files to ready to be processed - if ctime of file is less than ctime of next file in file ring buffer
    print ("Pcap files dir %s" %pcap_dir)    
    pcap_file_list = os.listdir(pcap_dir)
    pcap_file_list.sort()
    print ("- files found %s"%pcap_file_list)
    out_file= open('unified2_processed_files.txt', 'r+') 

    # go through list and remove entries that aren't files we care about
    to_be_removed = []
    
    # add your list to the var so that we exclude pcap files 
    #to_be_removed = ['snort.log.xxxxxx','snort.log.xxxxxx']
    
    for f in pcap_file_list:
        if not is_pcap(f):
            to_be_removed.append(f)
    for l in out_file.readlines():
        l=l.split("\n")[0]
        to_be_removed.append(l)
#    
    
    for f in to_be_removed:
        print ("Not pcap so not processing %s"%f)
        pcap_file_list.remove(f)
    
    num_pcap_files = len(pcap_file_list)
    pcap_file_dict = {}
        
    #print pcap_file_dict
      
    print ("NUMBER OF FILES IN FOLDER")
    print (len(pcap_file_list))
      
    sdpwd="S3cur!ty"
    
    for pf in pcap_file_list:
         pcap_snort=(pcap_dir+"/" + pf)         
         output_dirname =pf.split(".")[0]
         unified_cwd = pcap_dir + "/" + output_dirname
         d=glob.glob(unified_cwd+ '/*unified*')
         print ("current dir : %s" % unified_cwd)
         print ("current file : %s" % d[0])
         

      # barnyard cmd
      #sudo barnyard2 -c /etc/nsm/security-onion-eth0/barnyard2.conf  -o "snort.unified2.1483036626" -U  -l /mnt/hgfs/cdx_2009/sandbox_win/


         unified_cmd = "sudo barnyard2 -c /etc/nsm/security-onion-eth0/barnyard2.conf  -o %s -U  -l %s" %(d[0],unified_cwd)
         sn=unified_cmd.split()
         run_unified = subprocess.Popen(['sudo', '-S']+sn, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         #print(run_snort)         
         sudo_prompt = run_unified.communicate(sdpwd + '\n')[1]            
         run_unified.wait()
         pf+= ("\n")
         out_file.write(pf)
         out_file.flush()


            
        
    
    
    
    
    
main()
