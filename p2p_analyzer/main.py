#!/usr/bin/python
#!--*-- coding:utf-8 --*--
import tkFileDialog
import GLOBAL

try:
    from tkinter import *
except ImportError:  #Python 2.x
    PythonVersion = 2
    from Tkinter import *
    from tkFont import Font
    from ttk import *
    from tkMessageBox import *
import struct


class ARP_packet:
    def __init__(self):
        self.__Hardware_type=''
        self.__Protocol_type=''
        self.__Hardware_size=''
        self.__Protocol_size=''
        self.__Opcode=''
        self.__Sender_MAC_address=''
        self.__Sender_IP_address=''
        self.__Target_MAC_address=''
        self.__Target_IP_address=''


def str2mac(frame):
    MAC_address_1 = hex(int(struct.unpack("!B",frame[0:1])[0]))
    MAC_address_2 = hex(int(struct.unpack("!B",frame[1:2])[0]))
    MAC_address_3 = hex(int(struct.unpack("!B",frame[2:3])[0]))
    MAC_address_4 = hex(int(struct.unpack("!B",frame[3:4])[0]))
    MAC_address_5 = hex(int(struct.unpack("!B",frame[4:5])[0]))
    MAC_address_6 = hex(int(struct.unpack("!B",frame[5:6])[0]))
    MAC_address = str(MAC_address_1)[2:] +":"+\
                             str(MAC_address_2)[2:] +":"+ \
                             str(MAC_address_3)[2:] +":"+ \
                             str(MAC_address_4)[2:] +":"+ \
                             str(MAC_address_5)[2:] +":"+ \
                             str(MAC_address_6)[2:]
    return MAC_address

def str2ip(frame):
    IP_address_1 = int(struct.unpack("!B",frame[0:1])[0])
    IP_address_2 = int(struct.unpack("!B",frame[1:2])[0])
    IP_address_3 = int(struct.unpack("!B",frame[2:3])[0])
    IP_address_4 = int(struct.unpack("!B",frame[3:4])[0])
    IP_address= str(IP_address_1)+"."+str(IP_address_2)+"."+str(IP_address_3)+"."+str(IP_address_4)
    return IP_address

def new_file(fp):
    fp = open(fp,'rb')
    Magic,Major,Minor,ThisZone,SigFigs,SnapLen,Linktype = struct.unpack("!LhhLLLL",fp.read(24))
    if hex(int(Linktype))!='0x1000000':
        return -1
    try:
        while True:
            #分析数据报报头
            Timestamp_h,Timestamp_l = struct.unpack("!II",fp.read(8))
            Caplen,Packet = struct.unpack("II",fp.read(8))
            frame = fp.read(Caplen)
            analysis(frame)
            analysis(frame)
    finally:
        fp.close()

def analysis(frame):
    dst_mac = str2mac(frame[0:6])
    src_mac = str2mac(frame[6:12])
    if hex(int(struct.unpack("!H",frame[12:14])[0]))=="0x806":
        Hardware_type = hex(int(struct.unpack("!H",frame[14:16])[0]))
        Protocol_type = hex(int(struct.unpack("!H",frame[16:18])[0]))
        Hardware_size = int(struct.unpack("!B",frame[18:19])[0])
        Protocol_size = int(struct.unpack("!B",frame[19:20])[0])
        Opcode = int(struct.unpack("!H",frame[20:22])[0])
        Sender_MAC_address = str2mac(frame[22:28])
        Sender_IP_address= str2ip(frame[28:32])
        Target_MAC_address = str2mac(frame[32:38])
        Target_IP_address = str2ip(frame[38:42])
        rs="Hardware_type:"+str(Hardware_type)+"\n"+\
           "Protocol_type:"+str(Protocol_type)+"\n"+\
           "Hardware_size:"+str(Hardware_size)+"\n"+\
           "Protocol_size:"+str(Protocol_size)+"\n"+\
           "Opcode:"+str(Opcode)+"\n"+\
           "Sender_MAC_address:"+str(Sender_MAC_address)+"\n"+\
           "Sender_IP_address:"+str(Sender_IP_address)+"\n"+\
           "Target_MAC_address:"+str(Target_MAC_address)+"\n"+\
           "Target_IP_address"+str(Target_IP_address)
        GLOBAL.packet_type.insert(GLOBAL.packet_no,"ARP:who has:"+Target_IP_address+",tell:"+Sender_IP_address)
        GLOBAL.result.insert(GLOBAL.packet_no,rs)
        GLOBAL.packet_no=GLOBAL.packet_no+1


    if hex(int(struct.unpack("!H",frame[12:14])[0]))=="0x800":
        Version = hex(int(struct.unpack("!B",frame[14:15])[0]))[2]
        IHL = hex(int(struct.unpack("!B",frame[14:15])[0]))[3]
        ip_data_begin = 14 + int(IHL)*4
        Type_of_Service = hex(int(struct.unpack("!B",frame[15:16])[0]))
        Total_Length = int(struct.unpack("!H",frame[16:18])[0])
        Identification = int(struct.unpack("!H",frame[18:20])[0])
        Flags = bin(int(struct.unpack("!H",frame[20:22])[0]))[0:4]
        F_Reserved = Flags[0]
        F_Dont_Fragment = Flags[2]
        try:
            F_More_Fragment = Flags[3]
        except:
            F_More_Fragment = 0
        Fragment_Offset = bin(int(struct.unpack("!H",frame[20:22])[0]))
        Fragment_Offset = Fragment_Offset[0:1]+Fragment_Offset[2:]
        Fragment_Offset = int(Fragment_Offset,2)
        TTL = int(struct.unpack("!B",frame[22:23])[0])
        Protocol = int(struct.unpack("!B",frame[23:24])[0])
        IP_protocol_dict={
            1:"ICMP",
            2:"IGMP",
            6:"TCP",
            17:"UDP",
            50:"ESP(IPSec)",
            51:"AH(IPSec)",
            89:"OSPF"
        }
        Protocol_name=IP_protocol_dict.get(Protocol)
        Header_checksum = hex(struct.unpack("!H",frame[24:26])[0])
        Source_IP_address = str2ip(frame[26:30])
        Destination_IP_address = str2ip(frame[30:34])
        #跳过选项
        #IP数据报数据处理
        if Protocol_name == "TCP":
            Source_PORT_number = int(struct.unpack("!H",frame[ip_data_begin:ip_data_begin+2])[0])
            Destination_PORT_number = int(struct.unpack("!H",frame[ip_data_begin+2:ip_data_begin+4])[0])
            sequence_number = int(struct.unpack("!I",frame[ip_data_begin+4:ip_data_begin+8])[0])
            acknowledgement_number = int(struct.unpack("!I",frame[ip_data_begin+8:ip_data_begin+12])[0])
            tmp = int(struct.unpack("!B",frame[ip_data_begin+12:ip_data_begin+13])[0])
            Header_length = tmp>>4
            tcp_data_begin = int(Header_length) * 4 + ip_data_begin
            tmp = bin(struct.unpack("!B",frame[ip_data_begin+13:ip_data_begin+14])[0])
            tmp = tmp[0:1]+tmp[2:]
            FIN=tmp[-1:]
            if FIN=="":
                FIN="0"
            SYN=tmp[-2:-1]
            if SYN=="":
                SYN="0"
            RST=tmp[-3:-2]
            if RST=="":
                RST="0"
            PSH=tmp[-4:-3]
            if PSH=="":
                PSH="0"
            ACK=tmp[-5:-4]
            if ACK=="":
                ACK="0"
            URG=tmp[-6:-5]
            if URG=="":
                URG="0"
            window_size=struct.unpack("!H",frame[ip_data_begin+14:ip_data_begin+16])[0]
            #分析TCP数据
            # ip_data_begin+16和tcp_data_begin   中间相差的是IPTION
            message="None"
            if frame[tcp_data_begin:]!="":
                protocol_len = struct.unpack("!B",frame[tcp_data_begin:tcp_data_begin+1])[0]
                if protocol_len == 19:
                    protocol_name_1,protocol_name_2,protocol_name_3,protocol_name_4 = struct.unpack("!QQHB",frame[tcp_data_begin+1:tcp_data_begin+20])
                    protocol_name_1 = hex(protocol_name_1)[2:]
                    protocol_name_2 = hex(protocol_name_2)[2:]
                    protocol_name_3 = hex(protocol_name_3)[2:]
                    protocol_name_4 = hex(protocol_name_4)[2:]
                    protocol_name = protocol_name_1+protocol_name_2+protocol_name_3+protocol_name_4
                    protocol_name = protocol_name[0:16]+protocol_name[17:33]+protocol_name[34:]
                    if protocol_name == "426974546f7272656e742070726f746f636f6c":
                        message= "p2p found"
            rs = "Version:"+str(Version)+"\n"+\
                 "IHL:"+str(IHL)+"\n"+\
                 "Type_of_Service:"+str(Type_of_Service)+"\n"+\
                 "Total_Length:"+str(Total_Length)+"\n"+\
                 "Identification:"+str(Identification)+"\n"+\
                 "F_Reserved:"+str(F_Reserved)+"\n"+\
                 "F_Dont_Fragment:"+str(F_Dont_Fragment)+"\n"+\
                 "F_More_Fragment:"+str(F_More_Fragment)+"\n"+\
                 "Fragment_Offset:"+str(Fragment_Offset)+"\n"+\
                 "TTL:"+str(TTL)+"\n"+\
                 "Protocol:"+str(Protocol_name)+"\n"+\
                 "Header_checksum:"+str(Header_checksum)+"\n"+\
                 "Source_IP_address:"+str(Source_IP_address)+"\n"+\
                 "Destination_IP_address:"+str(Destination_IP_address)+"\n"+\
                 "Source_PORT_number:"+str(Source_PORT_number)+"\n"+\
                 "Destination_PORT_number:"+str(Destination_PORT_number)+"\n"+\
                 "sequence_number:"+str(sequence_number)+"\n"+\
                 "acknowledgement_number:"+str(acknowledgement_number)+"\n"+\
                 "URG,ACK,PSH,RST,SYN,FIN:"+str(URG)+","+str(ACK)+","+str(PSH)+","+str(RST)+","+str(SYN)+","+str(FIN)+"\n"+\
                 "window_size:"+str(window_size)+"\n"+\
                 "message:"+message
            GLOBAL.packet_type.insert(GLOBAL.packet_no,"TCP: From:"+str(Source_IP_address)+":"+str(Source_PORT_number)+" TO:"+str(Destination_IP_address)+":"+str(Destination_PORT_number))
            if message=="p2p found":
                GLOBAL.packet_type.insert(GLOBAL.packet_no,"Warn:P2P FOUDN,TCP: From:"+str(Source_IP_address)+":"+str(Source_PORT_number)+" TO:"+str(Destination_IP_address)+":"+str(Destination_PORT_number))
            GLOBAL.result.insert(GLOBAL.packet_no,rs)
            GLOBAL.packet_no=GLOBAL.packet_no+1

        if Protocol_name == "ICMP":
            Type = struct.unpack("!B",frame[ip_data_begin:ip_data_begin+1])[0]
            Type_dict={
                0:"Echo Reply",
                3:"Destination Unreachable",
                4:"Source Quench",
                5:"Redirect Message",
                8:"Echo Request",
                9:"Router Advertisement",
                10:"Router Solicitation",
                11:"Time Exceeded",
                12:"Parameter Problem: Bad IP header",
                13:"Timestamp",
                14:"Timestamp Reply",
                15:"Information Request",
                16:"Information Reply",
                17:"Address Mask Request",
                18:"Address Mask Reply",
                19:"Traceroute"
            }
            Type_name = Type_dict.get(Type)
            Code = struct.unpack("!B",frame[ip_data_begin+1:ip_data_begin+2])[0]
            checksum = struct.unpack("!H",frame[ip_data_begin+2:ip_data_begin+4])[0]
            rs = "Version:"+str(Version)+"\n"+\
                 "IHL:"+str(IHL)+"\n"+\
                 "Type_of_Service:"+str(Type_of_Service)+"\n"+\
                 "Total_Length:"+str(Total_Length)+"\n"+\
                 "Identification:"+str(Identification)+"\n"+\
                 "F_Reserved:"+str(F_Reserved)+"\n"+\
                 "F_Dont_Fragment:"+str(F_Dont_Fragment)+"\n"+\
                 "F_More_Fragment:"+str(F_More_Fragment)+"\n"+\
                 "Fragment_Offset:"+str(Fragment_Offset)+"\n"+\
                 "TTL:"+str(TTL)+"\n"+\
                 "Protocol:"+str(Protocol_name)+"\n"+\
                 "Header_checksum:"+str(Header_checksum)+"\n"+\
                 "Source_IP_address:"+str(Source_IP_address)+"\n"+\
                 "Destination_IP_address:"+str(Destination_IP_address)+"\n"+\
                 "Type_name:"+str(Type_name)+"\n"+\
                 "Code:"+str(Code)+"\n"+\
                 "checksum:"+str(checksum)
            GLOBAL.packet_type.insert(GLOBAL.packet_no,"ICMP: Type:"+Type_name)
            GLOBAL.result.insert(GLOBAL.packet_no,rs)
            GLOBAL.packet_no=GLOBAL.packet_no+1

        if Protocol_name == "UDP":
            Source_PORT_number = struct.unpack("!H",frame[ip_data_begin:ip_data_begin+2])[0]
            Destination_PORT_number = struct.unpack("!H",frame[ip_data_begin+2:ip_data_begin+4])[0]
            udp_total_length = struct.unpack("!H",frame[ip_data_begin+4:ip_data_begin+6])[0]
            rs = "Version:"+str(Version)+"\n"+\
                 "IHL:"+str(IHL)+"\n"+\
                 "Type_of_Service:"+str(Type_of_Service)+"\n"+\
                 "Total_Length:"+str(Total_Length)+"\n"+\
                 "Identification:"+str(Identification)+"\n"+\
                 "F_Reserved:"+str(F_Reserved)+"\n"+\
                 "F_Dont_Fragment:"+str(F_Dont_Fragment)+"\n"+\
                 "F_More_Fragment:"+str(F_More_Fragment)+"\n"+\
                 "Fragment_Offset:"+str(Fragment_Offset)+"\n"+\
                 "TTL:"+str(TTL)+"\n"+\
                 "Protocol:"+str(Protocol_name)+"\n"+\
                 "Header_checksum:"+str(Header_checksum)+"\n"+\
                 "Source_IP_address:"+str(Source_IP_address)+"\n"+\
                 "Destination_IP_address:"+str(Destination_IP_address)+"\n"+\
                 "Source_PORT_number:"+str(Source_PORT_number)+"\n"+\
                 "Destination_PORT_number:"+str(Destination_PORT_number)+"\n"+\
                 "udp_total_length:"+str(udp_total_length)
            GLOBAL.packet_type.insert(GLOBAL.packet_no,"UDP: From:"+str(Source_IP_address)+":"+str(Source_PORT_number)+" TO:"+str(Destination_IP_address)+":"+str(Destination_PORT_number))
            GLOBAL.result.insert(GLOBAL.packet_no,rs)
            GLOBAL.packet_no=GLOBAL.packet_no+1

class Application_ui(Frame):
    #这个类仅实现界面生成功能，具体事件处理代码在子类Application中。
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master.title('P2P分析')
        self.master.geometry('686x408')
        self.createWidgets()

    def createWidgets(self):
        self.top = self.winfo_toplevel()

        self.style = Style()

        self.VScroll1 = Scrollbar(self.top, orient='vertical')
        self.VScroll1.place(relx=0.56, rely=0., relwidth=0.025, relheight=0.826)

        self.List1Var = StringVar(value='List1')
        self.List1 = Listbox(self.top, listvariable=self.List1Var, yscrollcommand=self.VScroll1.set)
        self.List1.place(relx=0., rely=0., relwidth=0.561, relheight=0.833)
        self.List1['yscrollcommand']=self.VScroll1.set
        self.VScroll1['command'] = self.List1.yview

        self.Command2 = Button(self.top, text='退出', command=self.Command2_Cmd)
        self.Command2.place(relx=0.128, rely=0.882, relwidth=0.106, relheight=0.061)

        self.Command1 = Button(self.top, text='读取文件', command=self.Command1_Cmd)
        self.Command1.place(relx=0.023, rely=0.882, relwidth=0.095, relheight=0.061)

        self.style.configure('Label1.TLabel',anchor='w')
        self.Label1 = Label(self.top, text='Label1', style='Label1.TLabel')
        self.Label1.place(relx=0.595, rely=0., relwidth=0.386, relheight=0.924)

class Application(Application_ui):
    #这个类实现具体的事件处理回调函数。界面生成代码在Application_ui中。
    def __init__(self, master=None):
        Application_ui.__init__(self, master)
        self.List1.bind('<ButtonRelease-1>',self.List1_cmd)

    def Command1_Cmd(self, event=None):
        #TODO, Please finish the function here!
        GLOBAL.packet_no=0
        GLOBAL.result=[]
        self.Label1['text']=""
        self.List1.delete(0,END)
        fpath = tkFileDialog.askopenfilename()
        fp = open(fpath,'rb')
        Magic,Major,Minor,ThisZone,SigFigs,SnapLen,Linktype = struct.unpack("!LhhLLLL",fp.read(24))
        if hex(int(Linktype))!='0x1000000':
            return -1
        try:
                while True:
                    #分析数据报报头
                    Timestamp_h,Timestamp_l = struct.unpack("!II",fp.read(8))
                    Caplen,Packet = struct.unpack("II",fp.read(8))
                    frame = fp.read(Caplen)
                    analysis(frame)
        finally:
            print GLOBAL.packet_no
            print GLOBAL.result
            fp.close()
            for i in range(GLOBAL.packet_no):
                self.List1.insert(i,GLOBAL.packet_type[i])


    def Command2_Cmd(self, event=None):
        #TODO, Please finish the function here!
        exit()
    def List1_cmd(self,event=None):
        self.Label1['text']=GLOBAL.result[int(self.List1.curselection()[0])]

if __name__=='__main__':
    top = Tk()
    Application(top).mainloop()
    try: top.destroy()
    except: pass