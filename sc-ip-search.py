#!/usr/bin/python
# Written by: James Smith
# Version: 0.9 
# Created: May 3, 2018
#
# Given an IP range, this script will
#
# Set these environment variables to log in:
#     SCHOST
#     SCUSERNAME
#     SCPASSWORD
#
#
# Requires the following:
#   pip install pysecuritycenter
#   pip install ipaddr
#   pip install netaddr

from securitycenter import SecurityCenter5
import ipaddr
import json
import netaddr
import string
import os
import sys

###############################################
# CODE BELOW HERE - NOTHING TO CHANGE BY USER #
###############################################

def checkScanZones(sc,ipaddress):
	print("Beginning check of scan zones")
	#Download all the scanzone names
	resp=sc.get('zone?fields=name%2Cscanners%2CtotalScanners%2CactiveScanners%2CtotalScanners%2CmodifiedTime%2CcanUse%2CcanManage')

	#create an empty list of scan zone ranges
	scanzoneranges=[]

	#Iterate through all the scan zones and download the IP ranges
	for i in resp.json()['response']:
		#print "Examining scan zone \""+i['name']+"\""
		#print "id",i['id']
		resp=sc.get('zone/'+str(i['id'])+'?fields=name%2Cdescription%2CipList%2CcreatedTime%2Cranges%2Cscanners%2Cname%2Cscanners%2CtotalScanners%2CactiveScanners%2CtotalScanners%2CmodifiedTime%2CcanUse%2CcanManage')
		iplist=resp.json()['response']['ipList'].split(',')
		for j in iplist:
			#print "IP Range in scan zone",j

			#Check if the IP address is an IP range (instead of a single IP or CIDR)
			hyphen=string.find(j,"-")
			if( hyphen >= 0 ):
				#If the IP address is a range, convert it to CIDR notation
				#print "CIDRs",netaddr.iprange_to_cidrs(j[0:hyphen],j[hyphen+1:])
				for k in netaddr.iprange_to_cidrs(j[0:hyphen],j[hyphen+1:]):
					scanzoneranges.append([k,i])
			else:
				scanzoneranges.append([j,i])

	n2=ipaddr.IPNetwork(ipaddress)

	#Examine all the network ranges for overlaps
	#Go through all the ranges, comparing each one to all the other ranges,
	for i in range(0,len(scanzoneranges)):
		n1=ipaddr.IPNetwork(scanzoneranges[i][0])
		#print("Comparing "+str(scanzoneranges[i][0])+" with "+ipaddress)
		if n1.overlaps(n2):
			print("IP address "+str(n2) + " could be stored in scan zone '"+str(scanzoneranges[i][1]['name'])+"'\n\n")

	return(True)


def checkRepositories(sc,ipaddress):
	print("Beginning check of repositories")
	#Download all the scanzone names
	resp=sc.get('repository?fields=name%2Cdescription%2Ctype%2CdataFormat%2CvulnCount%2CremoteID%2CremoteIP%2Crunning%2CenableTrending%2CdownloadFormat%2ClastSyncTime%2ClastVulnUpdate%2CcreatedTime%2CmodifiedTime%2Corganizations%2Ccorrelation%2CnessusSchedule%2CipRange%2CipCount%2CrunningNessus%2ClastGenerateNessusTime%2Crunning%2Ctransfer%2CdeviceCount%2CtypeFields')

	#create an empty list of scan zone ranges
	repositoryranges=[]

	#Iterate through all the scan zones and download the IP ranges
	for i in resp.json()['response']:
		#print("Repository name: "+str(i['name']))
		#print("Repository range: "+str(i['typeFields']['ipRange']))

		ipranges=i['typeFields']['ipRange'].split(',')

		for j in ipranges:
			#print("IP range:",j)

			hyphen = string.find(j, "-")
			if (hyphen >= 0):
				#print("There are hyphens in the range")
				for k in netaddr.iprange_to_cidrs(j[0:hyphen], j[hyphen + 1:]):
					repositoryranges.append([k, i])
					#print("IP range:", k)
			else:
				repositoryranges.append([j, i])
				#print("IP range:",j)

	n2=ipaddr.IPNetwork(ipaddress)

	for i in range(0,len(repositoryranges)):
		n1=ipaddr.IPNetwork(repositoryranges[i][0])
		if n1.overlaps(n2):
			print("IP address "+str(n2) + " could be stored in repository '"+str(repositoryranges[i][1]['name'])+"' which has ranges "+str(repositoryranges[i][1]['typeFields']['ipRange'])+"\n\n")

	return(True)


def checkExclusionList(sc,ipaddress):
	print("Beginning check of exclusion lists")
	#Download all the scanzone names
	resp=sc.get('organization')

	#create an empty list of scan zone ranges
	restrictedranges=[]

	#Iterate through all the scan zones and download the IP ranges
	for i in resp.json()['response']:

		ipranges=i['restrictedIPs'].split(',')

		for j in ipranges:
			hyphen = string.find(j, "-")
			if (hyphen >= 0):
				for k in netaddr.iprange_to_cidrs(j[0:hyphen], j[hyphen + 1:]):
					restrictedranges.append([k, i])
			else:
				restrictedranges.append([j, i])

	n2=ipaddr.IPNetwork(ipaddress)

	for i in range(0,len(restrictedranges)):
		n1=ipaddr.IPNetwork(restrictedranges[i][0])
		if n1.overlaps(n2):
			print("IP address "+str(n2) + " is in the exclusion list for Organization '"+str(restrictedranges[i][1]['name'])+"' which has ranges "+str(restrictedranges[i][1]['restrictedIPs'])+"\n\n")

	return(True)



######################
###
### Program start
###
######################
# Look for SecurityCenter login information
if os.getenv('SCHOST') is None:
	schost = ""
else:
	schost = os.getenv('SCHOST')

if os.getenv('SCUSERNAME') is None:
	username = ""
else:
	username = os.getenv('SCUSERNAME')

if os.getenv('SCPASSWORD') is None:
	password = ""
else:
	password = os.getenv('SCPASSWORD')


if len(sys.argv) > 1:
        ipaddress=sys.argv[1]

# Create a session as the user
try:
	scconn = SecurityCenter5(schost)
except:
	print "Unable to connect to SecurityCenter"
	print("Make sure to set SCHOST, SCUSERNAME, and SCPASSWORD environment variables and export them.")
	exit(-1)

try:
	scconn.login(username, password)
except:
	print "Unable to log into SecurityCenter"
	print("Make sure to set SCHOST, SCUSERNAME, and SCPASSWORD environment variables and export them.")

print("Logged into SecurityCenter")
checkScanZones(scconn,ipaddress)
checkRepositories(scconn,ipaddress)
checkExclusionList(scconn,ipaddress)

exit()