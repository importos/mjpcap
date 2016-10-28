import mjpcap
import threading
import time
class unknown_packet(object):
    def __init__(self,p_type,data):
        self.data=data
        self.p_type=p_type
        pass
    def __str__(self):
        return 'unknown packet ['+self.p_type.encode('hex')+'] data >> '+self.data.encode('hex')
class ip_address(object):
    def __init__(self,data):
        self.addr=data
    def __str__(self):
        return str(ord(self.addr[0]))+'.'+str(ord(self.addr[1]))+'.'+str(ord(self.addr[2]))+'.'+str(ord(self.addr[3]))
class unknown_protocol(object):
    def __init__(self,protocol,data):
        self.data=data
        self.protocol=protocol
        pass
    def __str__(self):
        return 'unknown protocol ['+self.protocol+']data >> '+self.data.encode('hex')
class ICMP(object):
    def __init__(self,data):
        self.data=data
    def __str__(self):
        return 'ICMP protocol data >> '+self.data.encode('hex')
class IGMP(object):
    def __init__(self,data):
        self.data=data
        self.type=self.data[0].encode('hex')
        self.max=self.data[1].encode('hex')
        self.checksum=self.data[2:4].encode('hex')
        self.group_address=self.data[4:8].encode('hex')
        self.data=self.data[8:]
    def __str__(self):
        return 'IGMP protocol type('+self.type+') group address:'+self.group_address+' data >> '+self.data.encode('hex')
class TCP(object):
    def __init__(self,data):
        self.data=data
    def __str__(self):
        return 'TCP protocol data >> '+self.data.encode('hex')
class UDP(object):
    def __init__(self,data):
        self.data=data
        self.Source=self.data[0:2].encode('hex')
        self.Destination=self.data[2:4].encode('hex')
        self.Length=self.data[4:6].encode('hex')
        self.Checksum=self.data[6:8].encode('hex')
        self.data=data[8:]
    def __str__(self):
        return 'UDP protocol source:'+self.Source+' Destination:' +self.Destination+ ' data ['+self.Length+']>> '+self.data.encode('hex')
    
class IP_packet(object):
    def __init__(self,data):
        self.data=data
        (self.header_len,self.version)=self.data[0].encode('hex')
        self.tos=self.data[1].encode('hex')
        self.total_length=self.data[2:4].encode('hex')
        self.id=self.data[4:6].encode('hex')
        self.ttl=self.data[8].encode('hex')
        self.protocol=self.data[9].encode('hex')
        self.checksum=self.data[10:12].encode('hex')
        self.Source=ip_address(self.data[12:16])
        self.Destination=ip_address(self.data[16:20])
        self.data=self.data[20:]
        if self.protocol=='01':
            self.packet=ICMP(self.data)
        elif self.protocol=='02':
            self.packet=IGMP(self.data)
        elif self.protocol=='06':
            self.packet=TCP(self.data)
        elif self.protocol=='11':
            self.packet=UDP(self.data)
        else:
            self.packet=unknown_protocol(self.protocol,self.data)
    def __str__(self):
        return 'IP packet header_len('+self.header_len+') version:'+self.version+' Source: '+str(self.Source) +' Destination:'+str(self.Destination) +' packet:'+str(self.packet)

class ARP_packet(object):
    def __init__(self,data):
        self.data=data
    def __str__(self):
        return 'ARP packet data >>'+self.data.encode('hex')
        

class Ethernet(object):
    def __init__(self,data):
        self.source=data[:6]
        self.destination=data[6:12]
        self.type=data[12:14]
        self.data=data[14:]
        self.packet=None
        tt=self.type.encode('hex')
        if tt=='0800':
            self.packet=IP_packet(self.data)
        elif tt=='0806':
            self.packet=ARP_packet(self.data)
        else:
            self.packet=unknown_packet(self.type,self.data)
            
    def __str__(self):
        return 'Ethernet src:'+self.source.encode('hex')+'  dst:'+self.destination.encode('hex')+' type('+self.type.encode('hex')+') packet =>'+str(self.packet)
class packet_logger(threading.Thread):
    def __init__(self,interface):
        print '>>',interface
        threading.Thread.__init__(self)
        self.interface=interface
        self.interface.popen()
        self.id=self.interface.Id()
        self.hf=open('log_'+self.id+'.txt','wb')
    def stop(self):
        self.interface.pclose()
        self.interface=None
    def run(self):
        try:
            while (True):
                (res,packet)=self.interface.read()
##                print res
                if res>0:
                    eth_pkt=Ethernet(packet.data)
                    print self.id,eth_pkt
                    self.hf.write(str(eth_pkt))
                    self.hf.write('\r\n')
##                else:
##                    break
        except Exception,e:
            
            print self.id,e
        print 'Failed'
        self.interface.pclose()
        self.hf.close()
int1=mjpcap.interfaces()
print int1
lst_intl=[]
for itm in int1:
    p=packet_logger(itm)
    p.daemon=True
    p.start()
    lst_intl.append(p) 
try:
    while(True):
        time.sleep(1)
except :
    del int1
    for itm in lst_intl:
        itm.stop()
        itm.join()

