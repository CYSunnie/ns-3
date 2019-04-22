import subprocess
import re
import os
import netifaces
import random

# get port information according to its default route
if not os.path.exists('/etc/network/interfaces.d/pnet0.cfg'):
    try:
        routingGateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        routingNicName = netifaces.gateways()['default'][netifaces.AF_INET][1]

        for interface in netifaces.interfaces():
            if interface == routingNicName:
                # print netifaces.ifaddresses(interface)
                routingNicMacAddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
                try:
                    routingIPAddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
                    # TODO(Guodong Ding) Note: On Windows, netmask maybe give a wrong result in 'netifaces' module.
                    routingIPNetmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
                except KeyError:
                    pass
    except KeyError:
        pass
    # edit '/etc/network/interfaces.d/xx.cfg'
    with open('/etc/network/interfaces.d/eth0.cfg', 'r') as f:
        port_info_origin = f.readlines()
        port_info_origin = ''.join(port_info_origin)
        port_info_now = re.sub('iface eth0 inet.*', 'iface eth0 inet manual\n', port_info_origin, flags=re.DOTALL)
        with open('/etc/network/interfaces.d/eth0.cfg', 'w') as f:
            f.write(port_info_now)
    with open('/etc/network/interfaces.d/pnet0.cfg', 'w') as f:
        pnet0_info = 'auto pnet0\niface pnet0 inet static\n    address %s\n    netmask %s\n    gateway %s\n    bridge_ports eth0\n    bridge_maxwait 0\n    bridge_stp off\n    bridge_fd 0' \
                     % (routingIPAddr, routingIPNetmask, routingGateway)
        f.write(pnet0_info)
else:
    pass
def randomMAC():
        mac = [ 0x52, 0x54, 0x00,
                random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff) ]
        return ':'.join(map(lambda x: "%02x" % x, mac))
tapMac = randomMAC()
with open('/sys/class/net/eth0/address','r') as f:
    pnet0mac = f.read()
    print pnet0mac
# create 'pnet0' bridge and attatch the port to bridge
subprocess.call(['brctl', 'addbr', 'pnet0'])
subprocess.call(['brctl', 'addif', 'pnet0', 'eth0'])
subprocess.call(['ip', 'link', 'set', 'pnet0', 'address', pnet0mac])
subprocess.call(['ip', 'addr', 'flush', 'eth0'])
subprocess.call(['service', 'networking', 'restart'])
subprocess.call(['ip', 'route', 'add', '169.254.169.254', 'dev', 'pnet0'])
subprocess.call(['tunctl', '-t', 'mytap'])
subprocess.call(['ip', 'link', 'set', 'mytap', 'address', tapMac])
subprocess.call(['ip', 'link', 'set', 'mytap', 'up'])
subprocess.call(['brctl', 'addif', 'pnet0' ,'mytap'])
subprocess.call(['ip', 'link', 'set', 'eth0', 'promisc', 'on'])
subprocess.call(['ip', 'link', 'set', 'pnet0', 'promisc', 'on'])
subprocess.call(['ip', 'link', 'set', 'mytap', 'promisc', 'on'])
