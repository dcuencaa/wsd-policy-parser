#This script fetches all policies under a WSD base property and saves them in folder
#Instructions:
#	- Create an empty folder to save the policy files
#	- Run the script using Python 2.7 or higher
#Written by: David Cuenca (10 August 2018)

import json
import os
import sys
from pprint import pprint

from sys import version_info
py3 = version_info[0] > 2 #creates boolean value for test that Python major version > 2

if py3:
	bpid = input('\nEnter the base property_id: ')
	sect= input('\nEnter the edgerc section name: ')
	subfile = input('\nSave SubcustomerID file as: ')
	fold = input('\nName of folder where to save Policies: ')
else:
	bpid = raw_input('\nEnter the base property_id: ')
	sect= raw_input('\nEnter the edgerc section name: ')
	subfile = raw_input('\nSave SubcustomerID file as: ')
	fold = raw_input('\nSave Policies in folder: ')

command = "http --auth-type edgegrid -a "+sect+": :/partner-api/v2/network/production/properties/"+bpid+"/sub-properties > "+subfile

pprint("Executing: "+command)
os.system(command)
pprint("Saving Subcustomer-ID list file: "+subfile+"...")

with open(subfile) as fp:
    data = json.load(fp)

for el in data:
	command = "http --auth-type edgegrid -a "+sect+": :/partner-api/v2/network/production/properties/"+bpid+"/sub-properties/"+str(el['SubPropertyID'])+"/policy"
	os.system(command +" > " + fold + "/p_" + el["SubPropertyID"])
	pprint("writing policy: " + el["SubPropertyID"])
