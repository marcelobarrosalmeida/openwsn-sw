import os
import sys
from Tkinter import *
import tkMessageBox
import re
import threading
import struct
from pydispatch import dispatcher
import time

p = os.path.dirname(sys.argv[0])
p = os.path.join(p,'..','..','..','..','coap')
p = os.path.abspath(p)
sys.path.insert(0,p)

from coap import coap
from coap import coapDefines as d
import copy
import random
from Queue import Queue

class WorkerThread(threading.Thread):
    RANDOM_MAX_STARTUP_TIME = 1.5
    def __init__(self,ip):
        self.ip = ip
        self.answer = None
        self.coap = coap.coap(udpPort=self.get_random_port())
        self.crit_sec = threading.Lock()
        threading.Thread.__init__(self)
    
    def get_ip(self):
        return self.ip
    
    def get_answer(self):
        with self.crit_sec:
            v = copy.deepcopy(self.answer)
        return v
    
    def set_answer(self,v):
        with self.crit_sec:
            self.answer = copy.deepcopy(v)

    def wait_startup(self):
        time.sleep(random.random()*WorkerThread.RANDOM_MAX_STARTUP_TIME)

    def get_random_port(self):
        return random.randint(49152,65535)
        
    def cancel(self):
        self.coap.cancel()

class GetValueThread(WorkerThread):
    def __init__(self,ip):
        WorkerThread.__init__(self,ip)
        
    def run(self):
        self.wait_startup()
        try:
            uri = 'coap://[{0}]/s'.format(self.ip)
            r = self.coap.GET(uri)
        except Exception, e:
            self.set_answer({'error': repr(e)})
        else:
            self.set_answer({'id': r})

class GetIDThread(WorkerThread):
    def __init__(self,ip):
        WorkerThread.__init__(self,ip)
        
    def run(self):
        self.wait_startup()
        try:
            uri = 'coap://[{0}]/d'.format(self.ip)
            r = self.coap.GET(uri)
        except Exception, e:
            self.set_answer({'error': repr(e)})
        else:
            self.set_answer({'id': r})

        
class MainWorkerThread(threading.Thread):
    ID_ST, SCAN_ST = range(0,2)
    MAX_RETRIES = 5
    MAX_SCAN_TIMEOUT = 10
    def __init__(self):
        threading.Thread.__init__(self)
        self.running = False
        self.crit_sec = threading.Lock()
        self.mote_list = {}
        dispatcher.connect(self.add_mote,signal='ADD-MOTE',sender=dispatcher.Any)
        dispatcher.connect(self.del_mote,signal='DEL-MOTE',sender=dispatcher.Any)
        dispatcher.connect(self.quit,signal='QUIT',sender=dispatcher.Any)

    def add_mote(self,ip):
        with self.crit_sec:
            self.mote_list[ip] = {'STATE': MainWorkerThread.ID_ST, 'RETRIES':0}

    def del_mote(self,ip):
        with self.crit_sec:
            if self.mote_list.has_key(ip):
                del self.mote_list[ip]

    def quit(self):
        self.running = False

    def get_state_list(self,state):
        with self.crit_sec:
            lst = [ ip for ip,val in self.mote_list.iteritems() if val['STATE'] == state ]
        return lst

    def get_timed_out_list(self):
        with self.crit_sec:
            lst = [ ip for ip,val in self.mote_list.iteritems() if val['RETRIES'] >= MainWorkerThread.MAX_RETRIES ]
        return lst
    
    def get_id_list(self):
        return self.get_state_list(MainWorkerThread.ID_ST)

    def get_scan_list(self):
        return self.get_state_list(MainWorkerThread.SCAN_ST)

    def set_state(self,ip,v):
        with self.crit_sec:
            if self.mote_list.has_key(ip):
                self.mote_list[ip]['STATE'] = v;
        
    def set_retry(self,ip,v):
        with self.crit_sec:
            if self.mote_list.has_key(ip):
                self.mote_list[ip]['RETRIES'] = v;

    def add_retry(self,ip):
        with self.crit_sec:
            if self.mote_list.has_key(ip):
                print ip, self.mote_list[ip]['RETRIES']
                self.mote_list[ip]['RETRIES'] = self.mote_list[ip]['RETRIES'] + 1

    def run(self):
        self.running = True
        while self.running:
            if not self.mote_list:
                time.sleep(1)
                continue
            # cleanup list
            print 'cleanup list:', self.get_timed_out_list()
            for ip in self.get_timed_out_list():
                self.del_mote(ip)
                dispatcher.send(signal='MOTE-TIMED-OUT',ip=ip)
            # get ID tasks
            tasks = []
            ips = self.get_id_list()
            print 'get id list:', self.get_id_list()
            for ip in ips:
                t = GetIDThread(ip)
                t.start()
                tasks.append(t)
            # get value tasks
            ips = self.get_scan_list()
            print 'get val list:', self.get_scan_list()
            for ip in ips:
                t = GetValueThread(ip)
                t.start()
                tasks.append(t)
            # dispatch threads
            t2 = t1 = time.time()
            while (t2-t1) < MainWorkerThread.MAX_SCAN_TIMEOUT:
                time.sleep(1)
                not_ready = []
                ready = []
                error = []
                for t in tasks:
                    a = t.get_answer()
                    print a
                    if a == None:
                        not_ready.append(t)
                    elif a.has_key('error'):
                        error.append(t)
                    else:
                        ready.append(t)
                if not not_ready:
                    break
                t2 = time.time()
            for ip in ips:
                t.cancel()
            # mark timed out motes
            print 'not ready:', [ t.get_ip() for t in not_ready ]
            print 'ready:', [ t.get_ip() for t in ready ]
            print 'error:', [ t.get_ip() for t in error ]
            for t in error:
                dispatcher.send(signal='MOTE-ERROR',ip=ip,error=t.get_answer())
                self.add_retry(t.get_ip())
            for t in not_ready:
                self.add_retry(t.get_ip())
            for t in ready:
                self.add_retry(t.get_ip())
            # process motes that are answering
            for t in ready:
                ans = t.get_answer()
                ip = t.get_ip()
                self.set_retry(ip,0)
                if isinstance(t,GetIDThread):
                    self.set_state(ip,MainWorkerThread.SCAN_ST)
                    dispatcher.send(signal='NEW-MOTE-ID',ip=ip,mid=ans)
                else:
                    dispatcher.send(signal='NEW-MOTE-VALUE',ip=ip,value=ans)
                
        self.running = False
        
class SensorScannerGUI(object):
    def __init__(self, master):
        self.master = master
        self.ipv6_addr = StringVar()
        self.status = StringVar()
        self.mote = StringVar()
        self.status.set('')
        self.start = False
        self.msgq = Queue()
        self.crit_sec = threading.Lock()
        self.create_gui()
        dispatcher.connect(self.mote_timed_out,signal='MOTE-TIMED-OUT',sender=dispatcher.Any)
        dispatcher.connect(self.mote_error,signal='MOTE-ERROR',sender=dispatcher.Any)
        dispatcher.connect(self.new_mote_id,signal='NEW-MOTE-ID',sender=dispatcher.Any)
        dispatcher.connect(self.new_mote_value,signal='NEW-MOTE-VALUE',sender=dispatcher.Any)
        self.scan = MainWorkerThread()
        self.scan.start()
        self.master.mainloop()

    def mote_error(self,ip,error):
        with self.crit_sec:
            self.msgq.put(('LOG','Mote Error {0} {1}'.format(ip,error)))
            self.master.event_generate('<<ProcessMessage>>', when='tail')
            
    def mote_timed_out(self,ip):
        with self.crit_sec:
            self.msgq.put(('LOG','Mote timed out {0}'.format(ip)))
            self.master.event_generate('<<ProcessMessage>>', when='tail')
            
    def new_mote_id(self,ip,mid):
        with self.crit_sec:
            self.msgq.put(('LOG','New Mote ID {0} {1}'.format(ip,mid)))
            self.master.event_generate('<<ProcessMessage>>', when='tail')

    def new_mote_value(self,ip,value):
        with self.crit_sec:
            self.msgq.put(('LOG','Mote value {0} {1}'.format(ip,value)))
            self.master.event_generate('<<ProcessMessage>>', when='tail')
        
    def process_message(self,event):
        t,m = self.msgq.get()
        if t == 'LOG':
            self.add_log(m)
        elif t == 'STATUS':
            self.satus.set(m)
        self.master.update_idletasks()

    def add_log(self,msg=''):
        self.log.insert(END,msg + '\n')
        self.log.see(END)
        
    def add_mote(self):
        if self.validate_ipv6():
            ip = self.ipv6_addr.get()
            dispatcher.send(signal='ADD-MOTE',ip=ip)
            self.mote_list.insert(END,ip)
    
    def remove_mote(self):
        sel = self.mote_list.curselection()
        if sel:
            idx = int(sel[0])
            ip = self.mote_list.get(idx)
            self.mote_list.delete(idx)
            dispatcher.send(signal='DEL-MOTE',ip=ip)

    def start_stop(self):
        self.start = not self.start;
        if self.start:
            self.start_stop_bt['text'] = 'Stop'
        else:
            self.start_stop_bt['text'] = 'Start'
    
    def validate_ipv6(self):
        ipv6 = self.ipv6_addr.get().strip()
        self.ipv6_addr.set(ipv6)

        # http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        pattern = r"\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|" + \
            r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|" + \
            r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|" + \
            r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|" + \
            r":((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|" + \
            r"::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|" + \
            r"(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|" + \
            r"1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b"

        if re.match(pattern, ipv6):
            return True
        else:
            tkMessageBox.showwarning("IPv6","Invalid IPv6 address")
            return False

        return True

    def create_gui(self):
        self.master.wm_title("Sensor Data Scanner")

        f = Frame(self.master,padx=5,pady=5)
        Label(f,text="New Mote:").pack(side=LEFT,expand=NO)
        Entry(f,textvariable=self.ipv6_addr,width=20).pack(side=LEFT,expand=YES,fill=X)
        Button(f,text="Add",width=10,command=self.add_mote,default=ACTIVE).pack(side=LEFT,expand=NO)
        f.pack(side=TOP,fill=X)
        f = Frame(self.master,padx=5,pady=5)

        f1 = Frame(f,padx=5)
        Label(f1,text="Mote List:").pack(side=LEFT,expand=NO)
        #p = ['a','b','c']
        #OptionMenu(f, self.mote, *p).pack(side=LEFT,expand=YES,fill=X)
        self.list_ybar = Scrollbar(f1)
        self.list_ybar.pack(side=RIGHT, fill=Y)        
        self.mote_list = Listbox(f1,height=3,yscrollcommand=self.list_ybar.set)
        self.mote_list.pack(side=LEFT,expand=YES,fill=X)
        self.list_ybar.config(command=self.mote_list.yview)
        f1.pack(side=LEFT,expand=YES,fill=X)

        f2 = Frame(f)
        Button(f2,text="Remove",width=10,command=self.remove_mote,default=ACTIVE).pack(side=TOP,expand=NO)
        self.start_stop_bt = Button(f2,text="Start",width=10,command=self.start_stop,default=ACTIVE)
        self.start_stop_bt.pack(side=TOP,expand=NO)
        f2.pack(side=TOP,fill=X)

        f.pack(side=TOP,fill=X)

        f = Frame(self.master,padx=5,pady=5)
        self.log_ybar = Scrollbar(f)
        self.log_ybar.pack(side=RIGHT, fill=Y)
        ft=("courier new", 10, "normal")
        self.log = Text(f,width=60,height=15,font=ft,yscrollcommand=self.log_ybar.set)
        self.log.pack(side=TOP, expand=YES, fill=BOTH)
        self.log_ybar.config(command=self.log.yview)
        f.pack(side=TOP,expand=YES,fill=BOTH)

        f = Frame(self.master)
        Label(f,textvariable=self.status,anchor=W,relief=SUNKEN).pack(side=TOP,expand=YES,fill=X)
        f.pack(side=LEFT,expand=YES,fill=X)

        self.master.bind('<<ProcessMessage>>', self.process_message)

        self.master.protocol("WM_DELETE_WINDOW", self.close)
        
    def close(self):
        dispatcher.send(signal='QUIT')
        self.master.destroy()

SensorScannerGUI(Tk())


