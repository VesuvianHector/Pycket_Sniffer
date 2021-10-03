
import os
import sys
import subprocess

import Pycket_Hub
import Pycket_Start

#########################################################################################
#                                                                                       #
#   By: Johnathan T Heatherman                                                          #
#                                                                 #
#########################################################################################

if __name__ == '__main__':
	if sys.platform == "linux" or sys.platform == "linux2":#Check if it's linux
		if os.geteuid() == 0: #Check if we are root as we need to be root for the packet reader
			start = Pycket_Start.main()
			if start.continuee:
				Pycket_Hub.main(start.mac)
			else:
				sys.exit()
		else: #Runs the program in Sudo for us
			subprocess.call(['sudo', 'python3', *sys.argv]) #asks for sudo password to run program in root
			sys.exit()
	else:
		print("Your OS is not Linux this tool only works in linux")
		sys.exit()









