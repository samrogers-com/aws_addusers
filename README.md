# aws_addusers:

This script will add one or more users either by commandline or from a file.

It will first go and check if the user already has an account and if not create it and 
will put the user in the IAM group specified.

It will then create the AWS keys and write them out to a file as well as how to log into
the users AWS console.

You can either create a single account from the command line with -u & -g
or
You can create multi user account at once for a text file.

Options:
	-d, --debug	Turn on debug
	-i, --input, Input file name for mutli user account
	-o, --output, Output file name for each users keys
	-u, --user,  User name for a single user account
	-g, --group, Group name for a single user account
	-l, --list, List File name

Silicon Valley Research © 2013 

