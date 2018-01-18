#!/usr/bin/env python

"""

aws_addusers:

This script will add one or more users either by commandline or from a file.

It will first go and check if the user already has an account and if not create it and 
will put the user in the IAM group specified.

It will then create the AWS keys and write them out to a file as well as how to log into
the users AWS console.

Silicon Valley Research © 2013 

"""

import sys, os, boto, json, requests
import yaml, json, argparse
import subprocess as sub
import time, urllib2, glob, logging, logging.handlers
from pprint import pprint


__author__ = 'Sam Rogers'

parser = argparse.ArgumentParser(description='This is a Parser script by Sam.')
#parser.add_argument('-d','--debug', help='increase debug', action="store_true")
parser.add_argument('-d','--debug', help='increase debug', required=True)
parser.add_argument('-i','--input', help='Input file name',required=False)
parser.add_argument('-o','--output',help='Output file name', required=False)
parser.add_argument('-g','--group', help='Group name', required=False)
parser.add_argument('-l','--list', help='List File name', required=False)
parser.add_argument('-u','--user',  help='User name', required=False)
args = parser.parse_args()

LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

#LOG_FILENAME = '/tmp/logging_rotatingfile_example.out'
#LOG_FILENAME = 'aws-logging.out'

# Set up a specific logger with our desired output level
# create logger with 'add_userstogrp'
logger = logging.getLogger('add_userstogrp')
logger.setLevel(logging.DEBUG)
#h = logging.StreamHandler()
#h.setFormatter(logging.Formatter('%(message)s'))

# Add the log message handler to the logger
#handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=2000, backupCount=5)

#logging.getLogger().addHandler(handler)

#
# First create a connection to the IAM service
#
conn_iam = boto.connect_iam()
 
if args.debug:
	level_name = args.debug
	level = LEVELS.get(level_name, logging.NOTSET)
	logging.basicConfig(level=level,
								format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
								datefmt='%m-%d %H:%M',
								filename='aws-logging.out',
								filemode='w')
else:
	logging.basicConfig(level=logging.INFO,
								format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
								datefmt='%m-%d %H:%M',
								filename='aws-logging.out',
								filemode='w')

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
#console.setLevel(logging.ERROR)
console.setLevel(logging.CRITICAL)
# set a format which is simpler for console use
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
# tell the handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

logging.getLogger().addHandler(console)

logging.info('Does group Exist')
GrpName = ""

def does_group_exist(Group=GrpName):
	''' check user existed'''
	logging.getLogger('does_group_exist').info('Does group Exist')
	try:
		grp_response = conn_iam.get_group(Group)
		logging.info('Group does exist')
		return True
	except boto.exception.BotoServerError, e:
		logging.error('error %s doesn\'t exist ' % Group )
		return False

if args.group:
	GrpName = args.group
	does_group_exist(GrpName)
else:
	GrpName = "grid_devtest"

Path = ""

#logger.info("After open group file")

def getCredsFilename(UserName):
	User_Creds_Output_File = UserName + '_credentials.txt'
	return User_Creds_Output_File

def getCredsPwFilename(UserName):
	User_CredsPw_Output_File = UserName + '_pw_credentials.txt'
	return User_CredsPw_Output_File

def write_user_creds(UserName, User_Creds_Output_File, access_key_id, secret_access_key):
#	User_Creds_Output_File = getCredsFilename (UserName)
	print  "User_Creds_Output_File: %s" % User_Creds_Output_File
	UserCredsFile = open( User_Creds_Output_File, 'w' )
	UserCredsFile.write ('User Name,Access Key Id,Secret Access Key\n')
	UserCredsFile.write  ('"%s",%s,%s\n' % (UserName, secret_access_key, access_key_id))
	UserCredsFile.close()

def write_user_pwd(UsrName, UsrPasswd):
	UsrPwdFileName = getCredsPwFilename(UserName)  
	UsrPwdFile = open( UsrPwdFileName, 'w' )
	print  "UsrPwdFile: %s" % UsrPwdFileName
	UsrPwdFile.write ('User Name,Password,Direct Signin Link\n')
	UsrPwdFile.write ('"%s",%s,https://raleys.signin.aws.amazon.com/console' % (UsrName, UsrPasswd))
	UsrPwdFile.close() 

def get_user_pwd():
	cmdopssl = "/usr/bin/openssl rand -base64 14"
	output = sub.check_output(cmdopssl.split())
	Passwd =  output.strip('\n')
	return Passwd

def awk_user_pwd(UserName, CredsPwFilename):
	cmdawk = "/usr/bin/grep " + UserName + " " + CredsPwFilename + " | /usr/bin/awk -F, '{print $2}'"
#	cmdawk = "/usr/bin/grep " + UserName + " " + CredsPwFilename 
	output = sub.check_output(cmdawk, shell=True)
	Passwd =  output.strip('\n')
	return Passwd

def create_group(group=GrpName, path=Path, conn_iam=conn_iam):
	print "Creating {} group...".format(group),
	try:
		group = conn_iam.get_group(group)
	except boto.exception.BotoServerError, e:
		if e.error_code == "NoSuchEntity":
			group = conn_iam.create_group(group, path=path)
			print "success!"
	else:
		print "Group %s already exists, skipping." % GrpName


def create_user_profile(UserName, conn_iam):
	print ".Creating {} user Profile...\n".format(UserName),
	CredsPwFilename = getCredsPwFilename(UserName)

	if os.path.exists(CredsPwFilename):
		UsrPasswd = awk_user_pwd(UserName, CredsPwFilename)
		print "User Passwd %s already exists in %s ." % (UsrPasswd, CredsPwFilename)
	else:
		UsrPasswd = get_user_pwd()
		write_user_pwd(UserName, UsrPasswd)
		print "User: %s Password: %s has been created" % (UserName, UsrPasswd)

	try:
		user = conn_iam.get_login_profiles(UserName)
	except boto.exception.BotoServerError, e:
		if e.error_code == "NoSuchEntity":
			print "User %s Profile Has Been Created *** " % UserName
			user = conn_iam.create_login_profile(UserName, UsrPasswd)
	else:
		print "User %s Profile already exists, skipping." % UserName
		# I am forcing a password reset
		# I will need to put an option in here to force a password reset or not
		if os.path.exists(CredsPwFilename):
			try:
				user = conn_iam.update_login_profiles(UserName, UsrPasswd)
			except boto.exception.BotoServerError, e:
				print "Does Not work: Update UserName login profile!!!"
			else:
				print "UserName Login Profile has been Updated!"
			
def create_user(UserName, group=GrpName, conn_iam=conn_iam, path=Path):
	policies = []
	print "Creating {} user...\n".format(UserName),
	try:
		user = conn_iam.get_user(UserName)
	except boto.exception.BotoServerError, e:
		if e.error_code == "NoSuchEntity":
			user = conn_iam.create_user(UserName)
			response = conn_iam.create_access_key(UserName)
			print "success!"

			access_key_id = response.create_access_key_response .create_access_key_result.access_key.access_key_id
			secret_access_key = response.create_access_key_response .create_access_key_result.access_key.secret_access_key

			CredsFilename = getCredsFilename(UserName)
			if os.path.exists(CredsFilename):
				print "User %s Credintals file %s already exists." % (UserName, CredsFilename)
			else:
				write_user_creds(UserName, CredsFilename, access_key_id, secret_access_key)
				print "User %s Credintals file %s has been created." % (UserName, CredsFilename)

			print "AWS_ACCESS_KEY_ID = '{}'".format(access_key_id)
			print "AWS_SECRET_ACCESS_KEY = '{}'".format(secret_access_key)

#			for name, policy in policies.iteritems():
#				conn_iam.put_user_policy(UserName, name, policy)
#				print "\tAttaching {}".format(name)

#			Not sure where to put this
#			conn_iam.add_user_to_group(group, UserName)
#			print "\tAdding to {}".format(group)

			create_user_profile(UserName, conn_iam)
	else:
		print "%s already exists, skipping." % UserName
		create_user_profile(UserName, conn_iam)
#			Not sure where to put this
#		create_group(GrpName, Path, conn_iam)

def addUserToGroup(GrpName, UserName):
	''' Add user to existing Group
	:rtype : object
	'''
	logging.getLogger('addUserToGroup').info('Adding group ')
	try:
		grp_response = conn_iam.add_user_to_group(GrpName, UserName)
		logging.info('Add user to existing Group')
		return True
	except boto.exception.BotoServerError, e:
		logging.error('error %s Didn\'t Add user to existing Group' % GrpName )
		return False

#Test = args.test
if args.input:
	User_Creds_Input_File = args.input
	print ("Input file: %s" % User_Creds_Input_File )

if args.output:
	User_Creds_Output_File = args.output
	print ("Output file: %s" % User_Creds_Output_File )

if args.list:
	List_Filename = args.list
	List_Users = (line.rstrip('\n') for line in open(List_Filename))
	print ("List file: %s" % List_Filename )
	for UserName in List_Users:
		create_user(UserName, GrpName, conn_iam, Path)
		print ("User Name: %s" % UserName )
		if args.group:
			GrpName = args.group
			if does_group_exist(GrpName):
				addUserToGroup(GrpName, UserName)
		else:
			GrpName = "grid_devtest"
			
if args.user:
	UserName = args.user
	print ("User Name: %s" % UserName )
	create_user(UserName, GrpName, conn_iam, Path)
	if args.group:
		GrpName = args.group
		if does_group_exist(GrpName):
			addUserToGroup(GrpName, UserName)
	else:
		GrpName = "grid_devtest"
			
