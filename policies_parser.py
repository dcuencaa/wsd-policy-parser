#This script looks for a folder containing subcustomer policy files in json format
#Parses the policy files and creates two files:
#		1. Information file = a csv table with the information of the behaviors of the policies
#		2. Summary file = a csv table that shows a list of the supported behaviors in WSD and marks "Y" for the ones active in each policy
#Written by: David Cuenca (10 August 2018)

import json
import os
import sys
from pprint import pprint
from sys import version_info

py3 = version_info[0] > 2 #creates boolean value for test that Python major version > 2

#define the "behaviors" Classes
class bhv:	#Class for behaviors with type and value
    name = ""
    typ = ""
    value = ""
    enabl = "N"
    def description(self):
        desc_str = "%s,%s," % (self.typ, self.value)
        return desc_str

class bhv2:	#Class for behaviors with only value
    name = ""
    value = ""
    enabl = "N"
    def description(self):
        desc_str = "%s," % (self.value)
        return desc_str

#predefine the "behaviors" Objects to be used
#this is the list of possible behaviors in JSON policy
#add new behaviors here
orig_obj = bhv2()
cachqa_obj = bhv()
cach_obj = bhv()
content_char_obj = bhv2()
content_refresh_obj = bhv()
geo_blacklist_obj = bhv()
geo_whitelist_obj = bhv()
ip_blacklist_obj = bhv2()
ip_whitelist_obj = bhv2()
modify_path_obj = bhv()
referer_blacklist_obj = bhv2()
referer_whitelist_obj = bhv2()
site_fail_obj = bhv()
token_auth_obj = bhv2()

#information file headers
head_str = 	"rule,cache_type,cache_value,cachekey_query_type,cachekey_query_value,content_char_type,content_refresh_type,content_refresh_value,geo_blacklist_type,geo_blacklist_value,geo_whitelist_type,geo_whitelist_value,ip_blacklist_value,ip_whitelist_value,modify_path_type,modify_path_value,origin_value,referer_blacklist_value,referer_whitelist_value,site_fail_type,site_fail_alt_host,token_auth_type,"

#summary file headers
sum_head_str ="policy,cache,cache_query,content_char,content_refresh,geo_blacklist,geo_whitelist,ip_blacklist,ip_whitelist,modify_path,origin,referer_blacklist,referer_whitelist,site_fail,token_auth"

# Prompts for the folder path to look for policy files
if py3:
    pfolder_path = input('\nEnter the path of the folder containing the policies: ')
else:
    pfolder_path = raw_input('\nEnter the path of the folder containing the policies: ')

# If folder path ends with "/", then remove it
if pfolder_path.endswith("/"):
    pfolder_path = pfolder_path[:-1]

# Prompts for the name to save behaviors information csv file
if py3:
    fname = input('\nSave information file as: ')
else:
    fname = raw_input('\nSave information file as: ')

sumfname = "summary_" + fname	#name of the Summary file

#Open files in folder and store them in data json variable
for pol_name in os.listdir(pfolder_path):

	valid_json = False  # variable to determine if the file is a valid json (default is false)

	pprint("Opening Policy file:" + str(pol_name) + "...")

	with open(pfolder_path + "/" + pol_name) as polfile:
		#check if the file contains valid json data
	    try:
	        data = json.load(polfile)
	    except ValueError, e:
	    	pprint("WARNING!!!: NO JSON DATA FOUND in Policy file:" + str(pol_name) + "...")
	    else:
	    	valid_json = True

	#Insert here code to parse the json policy file and populate the behaviors table	

	# fname = "text1.txt"
	if os.path.isfile(fname):	#if information file exists then open to append new information 
		ftext = open(fname,"a+")
		ftext.write(str(pol_name) + ",") #add first colum cell - policy name + comma
	else:
		ftext = open(fname,"a+") #if information file does not exist then create and add headers row
		ftext.write("policy," + head_str + head_str + head_str + head_str + head_str + head_str + "\r\n" + str(pol_name) + ",")

	# sumfname = "summary_text1.txt"
	if os.path.isfile(sumfname):	#if summary file exists then open to append new information 
		sumftext = open(sumfname,"a+")
		sumftext.write(str(pol_name) + ",") #add first colum cell - policy name + comma
	else:
		sumftext = open(sumfname,"a+") #if summary file does not exist then create and add headers row
		sumftext.write(sum_head_str + "\r\n" + str(pol_name) + ",")


	if valid_json:
		#start parsing of json policy file
		for el in data:		
			rules = data["rules"]

			for body in rules:   #parses objects inside rules
				pprint("Parsing Policy file:" + str(pol_name) + "...")

				for matches in body["matches"]:   #parses matches
					
					#check if the file contains valid json data
				    try:
				        rule_match = str(matches["name"]+ " " + matches["value"])
				    except ValueError, e:
				    	rule_match = ("encoded-string")
					
				for behaviors in body["behaviors"]:		#parses behaviors
				
					#fills behaviors objects
					if behaviors["name"] == "caching":
						cach_obj.name = behaviors["name"]
						cach_obj.typ = behaviors["type"]
						cach_obj.value = behaviors["value"]
						cach_obj.enabl = "Y"

					elif behaviors["name"] == "cachekey-query-args":
						cachqa_obj.name = behaviors["name"]
						cachqa_obj.typ = behaviors["type"]
						cachqa_obj.value = behaviors["value"]
						cachqa_obj.enabl = "Y"

					elif behaviors["name"] == "content-characteristics":
						content_char_obj.name = behaviors["name"]
						content_char_obj.value = behaviors["type"]
						content_char_obj.enabl = "Y"

					elif behaviors["name"] == "content-refresh":
						content_refresh_obj.name = behaviors["name"]
						content_refresh_obj.typ = behaviors["type"]
						content_refresh_obj.value = behaviors["value"]
						content_refresh_obj.enabl = "Y"

					elif behaviors["name"] == "geo-blacklist":
						geo_blacklist_obj.name = behaviors["name"]
						geo_blacklist_obj.typ = behaviors["type"]
						geo_blacklist_obj.value = behaviors["value"]
						geo_blacklist_obj.enabl = "Y"

					elif behaviors["name"] == "geo-whitelist":
						geo_whitelist_obj.name = behaviors["name"]
						geo_whitelist_obj.typ = behaviors["type"]
						geo_whitelist_obj.value = behaviors["value"]
						geo_whitelist_obj.enabl = "Y"

					elif behaviors["name"] == "ip-blacklist":
						ip_blacklist_obj.name = behaviors["name"]
						ip_blacklist_obj.value = behaviors["value"]
						ip_blacklist_obj.enabl = "Y"

					elif behaviors["name"] == "ip-whitelist":
						ip_whitelist_obj.name = behaviors["name"]
						ip_whitelist_obj.value = behaviors["value"]
						ip_whitelist_obj.enabl = "Y"

					elif behaviors["name"] == "modify-outgoing-request-path":
						modify_path_obj.name = behaviors["name"]
						modify_path_obj.typ = behaviors["type"]
						modify_path_obj.value = behaviors["value"]
						modify_path_obj.enabl = "Y"

					elif behaviors["name"] == "origin":
						orig_obj.name = behaviors["name"]
						orig_obj.value = behaviors["params"]["originDomain"]
						orig_obj.enabl = "Y"

					elif behaviors["name"] == "referer-blacklist":
						referer_blacklist_obj.name = behaviors["name"]
						referer_blacklist_obj.value = behaviors["value"]
						referer_blacklist_obj.enabl = "Y"

					elif behaviors["name"] == "referer-whitelist":
						referer_whitelist_obj.name = behaviors["name"]
						referer_whitelist_obj.value = behaviors["value"]
						referer_whitelist_obj.enabl = "Y"

					elif behaviors["name"] == "site-failover":
						site_fail_obj.name = behaviors["name"]
						site_fail_obj.typ = behaviors["type"]
						site_fail_obj.value = behaviors["alternateHostname"]
						site_fail_obj.enabl = "Y"

					elif behaviors["name"] == "token-auth":
						token_auth_obj.name = behaviors["name"]
						token_auth_obj.value = behaviors["value"]
						token_auth_obj.enabl = "Y"

				#write behaviors information line in Information file. One line per policy
				pprint("Adding data to information file for:" + str(pol_name) + "...")
				ftext.write(rule_match + "," + cach_obj.description() + cachqa_obj.description() + content_char_obj.description()+ content_refresh_obj.description() + geo_blacklist_obj.description() + geo_whitelist_obj.description() + ip_blacklist_obj.description() + ip_whitelist_obj.description() + modify_path_obj.description() + orig_obj.description() + referer_blacklist_obj.description() + referer_whitelist_obj.description() + site_fail_obj.description() + token_auth_obj.description())

		ftext.write("\r\n")

	else:		
		ftext.write("NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA,NO_DATA," )
		ftext.write("\r\n")

	#write behaviors information line in Summary file. One line per policy
	pprint("Adding data to summary file for:" + str(pol_name) + "...")
	sumftext.write(cach_obj.enabl + "," + cachqa_obj.enabl + "," + content_char_obj.enabl + "," + content_refresh_obj.enabl + "," + geo_blacklist_obj.enabl + "," + geo_whitelist_obj.enabl + "," + ip_blacklist_obj.enabl + "," + ip_whitelist_obj.enabl + "," + modify_path_obj.enabl + "," + orig_obj.enabl + "," + referer_blacklist_obj.enabl + "," + referer_whitelist_obj.enabl + "," + site_fail_obj.enabl + "," + token_auth_obj.enabl)
	sumftext.write("\r\n")

                
