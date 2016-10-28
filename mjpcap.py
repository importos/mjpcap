import ctypes
from ctypes import wintypes




class sockaddr(ctypes.Structure):
    _fields_ =[("sa_family",ctypes.c_uint16),
               ("sa_data",ctypes.c_char_p)
               ]
class sockaddrin(ctypes.Structure):
    _fields_ =[("sin_family",ctypes.c_int16),
               ("sin_port",ctypes.c_uint16),
               ("sin_addr",ctypes.c_char_p),
               ("sin_zero",ctypes.c_char_p)
               ]
class pcap_addr(ctypes.Structure):
    pass

pcap_addr._fields_ =[
    ("next1",ctypes.POINTER(pcap_addr)),
    ("addr",ctypes.POINTER(sockaddrin)),
    ("netmask",ctypes.POINTER(sockaddrin)),
    ("broadaddr",ctypes.POINTER(sockaddrin)),
    ("dstaddr",ctypes.POINTER(sockaddrin))
    ]


PCAP_SRC_IF_STRING=ctypes.c_char_p( "rpcap://")



class pcap_if (ctypes.Structure):
    pass
pcap_if._fields_ =[("next1",ctypes.POINTER(pcap_if)),
                   ("name1",ctypes.c_char_p),
                   ("description1", ctypes.c_char_p),
                   ("adress",ctypes.POINTER(pcap_addr)),
                   ("flags",ctypes.c_uint)
                    ]


wpcap=ctypes.CDLL("wpcap.dll")
pcap_findalldevs=wpcap.pcap_findalldevs
pcap_findalldevs_ex=wpcap.pcap_findalldevs_ex
pcap_findalldevs_ex.restype=wintypes.DWORD
pcap_freealldevs=wpcap.pcap_freealldevs
pcap_open=wpcap.pcap_open
pcap_close=wpcap.pcap_close
pcap_next_ex=wpcap.pcap_next_ex
pcap_next_ex.restype=wintypes.DWORD

class address(object):
    def __init__(self,addr):
        pass
    pass
class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]
class pcap_pkthdr(ctypes.Structure):
    _fields_ =[("ts",timeval),
               ("caplen",ctypes.c_uint32),
               ("len",ctypes.c_uint32)]

class Packet_Header(object):
    def __init__(self,hdr,data):
        self.sec=hdr.contents.ts.tv_sec
        self.usec=hdr.contents.ts.tv_usec
        self.caplen=hdr.contents.caplen
        self.len=hdr.contents.len
        self.ptrdata=data
        self.data=ctypes.string_at(data,self.len)
        return
    def __str__(self):
        return "("+str(self.sec)+":"+str(self.usec)+")["+str(self.caplen)+","+str(self.len)+"]==>"+str(self.data.encode("hex"))
    pass
class interface(object):
    def __init__(self,inter):
        self.name=inter.name1
        self.desc=inter.description1
        self.adress=address(inter.adress)
        self.flags=inter.flags
        
        pass
    def Name(self):
        return self.name
    def Id(self):
        ind1=self.name.find('{')+1
        ind2=self.name.find('}')
        return self.name[ind1:ind2]
    def popen(self):
        self.terr=ctypes.create_string_buffer("\x00",256)
        self.fp=pcap_open(self.name,100,1,20,0x0,ctypes.byref(self.terr))
        print self.terr
        return
    def read(self):
        str1=ctypes.c_char_p()
        hdr=ctypes.pointer(pcap_pkthdr())
        res=pcap_next_ex(self.fp,ctypes.byref(hdr),ctypes.byref(str1))
        return (res,Packet_Header(hdr,str1))
    def pclose(self):
        return
    def __str__(self):
        return str(self.name)
    def __del__(self):
        pass
        
class interfaces(object):
    def __init__(self):
        self.bf1=ctypes.pointer(pcap_if())
        self.terr=ctypes.create_string_buffer("\x00",256)
        pcap_findalldevs_ex(PCAP_SRC_IF_STRING,0x0,ctypes.byref(self.bf1),ctypes.byref(self.terr))
        return
    def __iter__(self):
        self.ptr=self.bf1
        return self
    def next(self):
        if not self.ptr:
            raise StopIteration
        o1= self.ptr.contents
        self.ptr=self.ptr.contents.next1
        return interface(o1)
    def __del__(self):
        pcap_freealldevs(self.bf1)
    def __str__(self):
        o1=""
        cnt=0
        for itm in self:
            cnt+=1
            o1+=":"+str(cnt)+":"+str(itm)
        return o1


##
##
##
##if (==-1):
##    exit(0)
##p0=ctypes.POINTER(pcap_if)
##p0=bf1
##while(p0):
##    print p0.contents.name1
##    print p0.contents.decription1
##    ad1=p0.contents.adress
##    while(ad1):
##        print ad1.contents.addr.contents.sin_family
##        print ad1.contents.addr.contents.sin_port
##        print ad1.contents.addr.contents.sin_addr
##        ad1=ad1.contents.next1
##    
##    p0=p0.contents.next1
##pcap_freealldevs(bf1)
