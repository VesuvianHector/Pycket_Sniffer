# Used for the GUI of the program
import queue
import signal
import threading
import logging
import tkinter as tk
from tkinter.scrolledtext import ScrolledText as ST
from tkinter import ttk, N ,S, E, W


from pysniff_tools import Pysniff as pyt


"""File used for containing all the tkinter and threads for the first screen in the GUI """


logger = logging.getLogger(__name__)


class MAC_ADDR_DISPLAY:
    """ This is where we keep the scrolled text stuff as it has alot going on.

     So i felt it was best to keep it in a separate class for ease of reading the code
    """

    def __init__(self, fram):
        self.fram = fram

        # ScrolledText wdiget

        self.scrolled_text = ST(fram, state='disabled', height=12)
        self.scrolled_text.configure(font="TkDefualtFont", background='teal')
        self.scrolled_text.tag_config('INFO', foreground='light blue')
        self.scrolled_text.tag_config('DEBUG', foreground='gray')
        self.scrolled_text.pack()
        # Create a logging handler using a queue
        self.log_queue = queue.Queue()
        self.handler = QueueHandler(self.log_queue)
        formatter = logging.Formatter('%(message)s')
        self.handler.setFormatter(formatter)

        logger.addHandler(self.handler)

        # Start polling messages from the queue
        self.yolo = self.fram.after(100, self.QueueLog)



    def display(self, record):
        """Displays the found mac ADDR to the scroll text widget"""

        msg = self.handler.format(record)
        self.scrolled_text.configure(state='normal')
        self.scrolled_text.insert(tk.END, msg + '\n', record.levelname)
        self.scrolled_text.configure(state='disabled')
        # Autoscroll to the bottom
        self.scrolled_text.yview(tk.END)


    def QueueLog(self):
        """Method for helping us load items from the queue into the display function
         as they are added from a seperate Thread"""
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





class StartMenu:

    def __init__(self, windoor):
        self.mac       = ""  # Initializer
        self.counter   = 0
        self.windoor   = windoor
        self.continuee = False

        self.Get_MAC_C = Get_MAC_ADDR()
        self.Get_MAC_C.start()

        self.console_fram = tk.ttk.Frame(windoor)
        self.fram         = MAC_ADDR_DISPLAY(self.console_fram)
        self.windoor.configure(bg='black')
        spaceplace = (" " * 100)
        windoor.title("Pycket_Sniffer")
        Title             = tk.Label(self.windoor, text="Pycket_Sniffer", font='Courier', foreground='teal')
        Title.pack()
        label             = tk.Label(self.windoor,
                                     text='Please Type the index of the Mac Address you wish to sniff here',
                                     foreground='teal')
        self.console_fram.pack()
        self.view         = self.fram.scrolled_text
        self.index        = tk.StringVar()
        enter             = tk.Entry(self.windoor, font='Courier', textvariable=self.index,
                                     foreground='white', background='teal')

        launcher          = tk.Button(self.windoor, text="Enter", foreground='teal', background='white',
                                      command=lambda: self.get_MAC())

        # Order in which these items will be displayed from top to bottom

        label.pack()
        enter.pack()
        launcher.pack()  # foo.pack() is the method to allow us to directly display each item



        self.windoor.protocol('WM_DELETE_WINDOW', self.quit)
        self.windoor.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def launch(self, mac):
        self.windoor.destroy()
        self.Get_MAC_C.stop()
        self.mac       = mac
        self.continuee = True

    def get_MAC(self):
        mac      = self.index.get()
        strwing  = str(self.view.get("1.0", tk.END))
        listy    = strwing.split("\n")
        new_addr = listy[int(mac) - 1]
        listy    = new_addr.split(" ")
        new_addr = listy[2]
        self.launch(new_addr)

    def quit(self):
        self.Get_MAC_C.stop()
        self.console_fram.after_cancel(self.fram.yolo)
        self.windoor.destroy()


class Get_MAC_ADDR(threading.Thread):
    """
    Class to Grab the MAC ADDRESSES and to log it so that it may get displayed in the GUI
    This Runs on a seperate thread then the rest of the GUI
    """

    def __init__(self):
        super().__init__()
        self._stop_event = threading.Event()
        self.listy = []
        self.counter = 0

    def run(self):
        while not self._stop_event.is_set():
            macget = pyt()
            packet1 = macget.deviceFinder
            if packet1 not in self.listy:
                self.listy.append(packet1)
                self.counter = (self.counter + 1)
                packet1      = (str(self.counter) + " " + packet1)
                level        = logging.INFO
                logger.log(level, packet1)
            else:
                continue

    def stop(self):
        self._stop_event.set()


def main():
    logging.basicConfig(level=logging.DEBUG)
    windoor = tk.Tk()
    end     = StartMenu(windoor)
    end.windoor.mainloop()
    return end

