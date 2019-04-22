import os
os.chdir("/etc/network/interfaces.d")
os.system("rm pnet0.cfg")
os.system("sed -i 's/manual/dhcp/g' eth0.cfg")