
import logging
import queue
import signal
import threading


import tkinter as tk
from tkinter.scrolledtext import ScrolledText as ST
from tkinter import ttk, N, S, E, W

from pysniff_tools import Pysniff as pyt


logger = logging.getLogger(__name__)


"""File used for containing all the methods and classes contained in the second screen of the GUI"""


class Hub:
    """Main part of the GUI where we keep all of the other stuff"""

    def __init__(self, windoor, mac):
        self.windoor = windoor
        self.Pause   = True
        self.ButtTxt = tk.StringVar()
        self.ButtTxt.set("Pause")
        self.windoor.configure(bg="black")

        self.PacketReader = PacketReader(mac)
        self.PacketReader.start()



        windoor.title("""Reading Packets For:\n""" + mac)
        windoor.columnconfigure(0, weight=1)
        windoor.rowconfigure(2, weight=1)
        console_fram  = tk.ttk.Frame(windoor)
        console_fram.grid(column=0, row=0, sticky=(N, W, E, S))
        console_fram.columnconfigure(0, weight=1)
        console_fram.rowconfigure(0, weight=1)
        self.console  = ScrollTXT(console_fram, mac)
        self.butt     = tk.Button(windoor, height=3, textvariable=self.ButtTxt, command=lambda : self.Pause_Start(mac))
        self.butt.grid(column=0, row=1, sticky=(N, S, E, W))



        self.windoor.protocol('WM_DELETE_WINDOW', self.quit)
        self.windoor.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)


    def Pause_Start(self, mac):

        "Command to start and stop the packet reading"

        if self.Pause == True:
            self.Pause   = False
            self.ButtTxt.set("Resume")
            self.PacketReader.stop()

        else:
            self.Pause   = True
            self.ButtTxt.set("Pause")
            self.PacketReader.run()




    def quit(self):
        self.PacketReader.stop()
        self.windoor.destroy()


class ScrollTXT:
    """ This is where we keep the scrolled text stuff as it has alot going on.

     So i felt it was best to keep it in a separate class for ease of reading the code
    """

    def __init__(self, fram, mac):
        self.fram = fram
        
        #ScrolledText wdiget
        
        self.scrolled_text = ST(fram, state='disabled', height=15, width=120)
        self.scrolled_text.grid(row=0, column=0, sticky=(S, N, W, E))
        self.scrolled_text.configure(font='TkFixedFont', background='black')
        self.scrolled_text.tag_config('INFO', foreground='green', background='black')
        self.scrolled_text.tag_config('DEBUG', foreground='gray')
       
        # Create a logging handler using a queue
        self.log_queue = queue.Queue()
        self.handler   = QueueHandler(self.log_queue)
        formatter      = logging.Formatter('%(message)s') #This formats the Log into Strings for us
        self.handler.setFormatter(formatter)
        logger.addHandler(self.handler)
        # Start polling messages from the queue
        self.fram.after(100, self.QueueLog)

    def display(self, record):
        msg = self.handler.format(record)
        self.scrolled_text.configure(state='normal')
        self.scrolled_text.insert(tk.END, msg + '\n', record.levelname)
        self.scrolled_text.configure(state='disabled')
        # Autoscroll to the bottom
        self.scrolled_text.yview(tk.END)

    def QueueLog(self):
        # Check every 100ms if there is a new message in the queue to display
        while True:
            try:
                record = self.log_queue.get(block=False)
            except queue.Empty:
                break
            else:
                self.display(record)
        self.fram.after(100, self.QueueLog)


class QueueHandler(logging.Handler):
    """Class to send logging records to a queue

    It can be used from different threads
    """

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, mac):
        self.log_queue.put(mac)


class PacketReader(threading.Thread):
    """
    Class to launch the packet sniffing and to log it so that it may get displayed in the GUI
    """

    def __init__(self, mac):
        super().__init__()
        self._stop_event = threading.Event()
        self.mac         = mac

    def run(self):
        while not self._stop_event.is_set():

            macget = pyt()
            packet = macget.Get_Packets(self.mac)
            level  = logging.INFO
            logger.log(level, packet)
    def stop(self):
        self._stop_event.set()



def main(mac):
    logging.basicConfig(level=logging.DEBUG)
    windoor        = tk.Tk()
    ScrollTXTsreen = Hub(windoor, mac)
    ScrollTXTsreen.windoor.mainloop()

