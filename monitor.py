
vim #!/usr/bin/env python 
# -*- coding:utf-8 -*-
import os
import glob
import time
#标记ns3蠕虫程序是否在运行中
i = 0
def monitor():
	global i
	try:
		file = glob.glob("".join(["/root/control*"]))
		with open(file[0],'r') as f:
			signal = f.read().strip()
	except:
		return
	if signal == '1' and i == 0:
		i = 1
		os.system('curl -X GET http://127.0.0.1:20904/start')
	elif signal == '0' and i == 1:
		i=0
                os.system('curl -X GET http://127.0.0.1:20904/stop')
		os.system('0>/root/infection_data.out')
        else:
                return
if __name__ == '__main__':
        while True:
                monitor()
				time.sleep(1)
