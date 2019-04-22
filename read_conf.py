#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#nohup python conf.py & 需要设置开机自启动
#启动：curl -X GET http://127.0.0.1:20904/start
#停止：curl -X GET http://127.0.0.1:20904/stop
import os
import json
import signal
import bottle
import re
import glob
import time
from httpclient import HttpClient
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 20904

app = bottle.Bottle()
i = 0
@app.route('/start')
def start():
	use_user_data_flag = True
	try:
		user_data_url = 'http://169.254.169.254/latest/user-data'
		response = HttpClient(method='GET', url=user_data_url).process
		status_code = response.status_code
		if status_code != 200:
			use_user_data_flag = False
		else:
			conf = response.json()
	except:
		use_user_data_flag = False

	if not use_user_data_flag:
		file = glob.glob("".join(["/root/conf*.json"]))
		global i
		while True:
			try:
				conf=json.load(open(file[0],'r'))
			except(IOError,ValueError):
				time.sleep(5)
				continue
			else:
				break
	if conf.has_key('udp_worm'):
		conf1=conf['udp_worm']
		local_network = conf1['local_network']
		node_number = conf1['node_number']
		KVM_gateway_address = conf1['KVM_gateway_address']
		scan_ip_from = conf1['scan_ip_from']
		scan_ip_to = conf1['scan_ip_to']
		scan_interval = conf1['scan_interval']
		scan_port = conf1['scan_port']
		worm_behavior = conf1['worm_behavior']
		if(i==0):
			os.system('route del -net default')
			os.system('route add -net default gw %s'% KVM_gateway_address)
		if(worm_behavior):
			cmd = 'nohup ./waf --run "scratch/udpcli-socket --scan_ip_from=%s --scan_ip_to=%s --scan_port=%s --scan_interval=%s --local_network=%s --node_number=%s --KVM_gateway_address=%s" > /root/infection_data.out &' % (scan_ip_from,scan_ip_to,scan_port,scan_interval,local_network,node_number,KVM_gateway_address)
		else:
			cmd = 'nohup ./waf --run "scratch/udpdst-socket --scan_ip_from=%s --scan_ip_to=%s --scan_port=%s --scan_interval=%s --local_network=%s --node_number=%s --KVM_gateway_address=%s" > /root/infection_data.out &' % (scan_ip_from,scan_ip_to,scan_port,scan_interval,local_network,node_number,KVM_gateway_address)
		
	elif conf.has_key('tcp_background'):
		conf1=conf['tcp_background']
		local_network = conf1['local_network']
		node_number = conf1['node_number']
		KVM_gateway_address = conf1['KVM_gateway_address']
		service_net_from = conf1['service_net_from']
		service_net_to = conf1['service_net_to']
		service_port = conf1['service_port']
		probability_client = conf1['probability_client']
		cmd = 'nohup ./waf --run "scratch/tcp --service_net_from=%s --service_net_to=%s --service_port=%s --local_network=%s --node_number=%s --KVM_gateway_address=%s --probability_client=%s" > /root/tcp.out &' % (service_net_from,service_net_to,service_port,local_network,node_number,KVM_gateway_address,probability_client)
	else:
		print('Please set right mode!')
		exit(1)
	os.chdir('/root/ns-allinone-3.21/ns-3.21/')
	os.system(cmd)
@app.route('/stop')
def stop():
	wafpid = os.popen('ps aux | grep -E "udp|tcp" | grep -v grep')
	wafpid = wafpid.read().splitlines()
	for i in wafpid:
		pid = re.search('\d+',i)
		pid = pid.group()
		try:
			os.kill(int(pid),signal.SIGKILL)
		except OSError:
			continue
		else:
			print('Process over...')
			

if __name__=='__main__':
	app.run(host=DEFAULT_HOST, port=DEFAULT_PORT)
