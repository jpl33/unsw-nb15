#!/usr/bin/env python

import os
import datetime
import subprocess
import sys
import pathlib
import itertools
import numpy as np
from array import array
import pandas as pd

from subprocess import Popen, PIPE
from os import path
from pathlib import Path
import logging



#pcap_dir = "/mnt/hgfs/cdx_2009/sandbox_win"
home_dir='D:\\personal\\msc\\maccdc_2012\\'
pcap_dir= 'maccdc2012_00003\\'
pcap_name= 'maccdc2012_00001'
pcap=(".pcap",".dmp",",pcapng")
conn_frmt=['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents','orig_cc','resp_cc','sensorname']
snrt_frmt=['timestamp','sig_generator','sig_id','sig_rev','msg','proto','src','srcport','dst','dstport','ethsrc','ethdst','ethlen','tcpflags','tcpseq','tcpack','tcplen','tcpwindow','ttl','tos','id','dgmlen','iplen','icmptype','icmpcode','icmpid','icmpseq']

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
hdr=0
def is_header(file):
    if (file.readline().split(" ")[0]=="File"):
       hdr=1
       
    
        
        
def main():
    
    
    # Get list of PCAP files to ready to be processed - if ctime of file is less than ctime of next file in file ring buffer
    print ("Pcap files dir %s" %home_dir)    
    pcap_file_list = os.listdir(home_dir)
    pcap_file_list.sort()
    print ("- files found %s"%pcap_file_list)
    out_file= open('pcap_info.txt', 'r+')
    prcf_file= open('processed_files.txt', 'r+')
    is_header(out_file)
    # go through list and remove entries that aren't files we care about
    to_be_removed = []
    
    # add your list to the var so that we exclude pcap files 
    #to_be_removed = ['snort.log.xxxxxx','snort.log.xxxxxx']
    
    for f in pcap_file_list:
        if not is_pcap(f):
            to_be_removed.append(f)
    for l in prcf_file.readlines():
        l=l.split("\n")[0]
        to_be_removed.append(l)
    
    
    for f in to_be_removed:
        print ("Not pcap so not processing %s"%f)
        pcap_file_list.remove(f)
    
    num_pcap_files = len(pcap_file_list)
    pcap_file_dict = {}
        
    #print pcap_file_dict
      
    print ("NUMBER OF FILES IN FOLDER")
    print (len(pcap_file_list))
    alrt_sum=pd.DataFrame()   
    srvc_sum=pd.DataFrame()
    
    sdpwd="S3cur!ty"
    print ("running capinfo")
    for pf in pcap_file_list:
         print ("current file : %s" % pf)
        # since snort takes so long to start up, only run it once at the end on all the pcap files at once
         pcap_name =pf.split(".")[0]
         pcap_snort=(home_dir + pf)         

         #is__dir(pcap_dir,output_dirname)
         if (hdr==0):
            # capinfos_cmd = "sudo capinfos -m -a -e -r -T %s" %(pcap_snort)
            win_cmd="capinfos -m -c -a -e -r -T %s" %(pcap_snort)
         else:
             #capinfos_cmd = "sudo capinfos -m -a -e -T %s" %(pcap_snort)
             win_cmd="capinfos -m -c -a -e -T %s" %(pcap_snort)
             
         #sn=capinfos_cmd.split()
         
         wn_cmd=win_cmd.split()
         #run_capinfos = subprocess.Popen(['sudo', '-S']+sn, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         #run_capinfos = subprocess.check_output(['sudo', '-S']+sn, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         
         run_win_cmd = subprocess.check_output(wn_cmd, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         
         df_conn = pd.read_csv(home_dir+pcap_name+'\\' +'conn.log',sep='\t',comment='#',names=conn_frmt)
         srvc_nm=df_conn['service'].value_counts()
         srvc_nm=srvc_nm.to_frame()
         srvc_nm['file']=pcap_name
         alrt = pd.read_csv(home_dir+pcap_name+'\\'+'alert.csv',sep=',',comment='#',names=snrt_frmt)
         df=alrt.groupby(['msg','sig_id','sig_rev']).size()
         df=df.to_frame()
         df.columns=['count']
         idx_msg=[]
         ard=array('i',df.index.levels[1].values)
         for id in df.index.levels[0]:
             ds=df.xs(id,level=0,axis=0)
             if len(ds)>1:
                 print(id)
                 ii=ds.iloc[0]['count']+ds.iloc[1]['count']
                 df.loc[id]['count']=ii
                 idx_msg.append(ds.index.levels[0][ds.index.labels[0][0]])
         
         if len(idx_msg)>0:
             df=df.drop(idx_msg,level=1)
             for j in idx_msg:
                 ard_id=np.where(ard==j)
                 ard2=np.delete(ard,ard_id)
                 ard=ard2
         df['msg']=df.index.levels[0]
         #df.index.levels[0][0:len(df.index.levels[0])]
         
         df['sig_id']=ard
         i=0
         ar=array('i',[0])
         for _ in itertools.repeat(1,len(df)-1):
             i+=1
             ar.append(i)
         idx=pd.Index(ar)
         df=df.set_index(idx,drop=True)
         df['file']=pcap_name
         alrt_sum=alrt_sum.append(df)
         srvc_sum=srvc_sum.append(srvc_nm)
         out_file.write('\n'+run_win_cmd)
         out_file.write('\n'+srvc_nm.to_csv())
         out_file.write('\n'+df.to_csv())
         out_file.flush()
         
         prcf_file.write("\n"+pf)
         prcf_file.flush()
         
    alrt_file= open('alert_summary.csv', 'r+')
    srvc_file= open('service_summary.csv', 'r+')
    i=0
    ar=array('i',[0])
    for _ in itertools.repeat(0,len(alrt_sum)-1):
        i+=1
        ar.append(i)
    idx=pd.Index(ar)
    alrt_sum=alrt_sum.set_index(idx,drop=True)
    alrt_file.write(alrt_sum.to_csv())
    srvc_file.write(srvc_sum.to_csv())
    alrt_file.flush()
    srvc_file.flush()
           
        
    
    
    
    
    
main()
