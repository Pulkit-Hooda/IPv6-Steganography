import argparse
import subprocess
from tkinter import Button,Toplevel,Label,StringVar,Entry,Tk,scrolledtext,WORD,INSERT
import tkinter as tk
import sys
from receiver import reciever_main,stop_event,delete_firewall_rule
from sender import sender_main

def destroy(t):
    t.destroy()

def destroy_receiver(t):
    stop_event.set()
    t.destroy()

def destroy_all(t):
    stop_event.set()
    t.destroy()
    #subprocess.run('taskkill /f /im python.exe')

def send_func(ip,msg,key,scroll,myip,interface):
    val = msg.get()
    msg.clipboard_clear()
    sender_main(ip,val,key,scroll,myip,interface)

def send_window():
    t = Toplevel()
    t.resizable(0, 0)
    t.geometry("430x400")
    t.title("Send Your Message")
    t.configure(bg="#2C3E50")

    Label(t, text="IPv6 Hidden Message Sender", font=("Helvetica", 15, "bold"), fg='white', bg='#34495E', pady=10).pack(fill="x")
    
    Label(t, text="Enter Destination IPv6:", font=("Helvetica", 11), fg='white', bg='#2C3E50').place(x=20, y=60)
    ip = StringVar()
    dip = Entry(t, textvariable=ip, font=("Helvetica", 11), bg="#ECF0F1", bd=2, relief="solid")
    dip.place(x=180, y=60, width=230)

    Label(t, text="Enter your Message:", font=("Helvetica", 12), fg='white', bg='#2C3E50').place(x=20, y=100)
    msg = StringVar()
    dmsg = Entry(t, textvariable=msg, font=("Helvetica", 11), bg="#ECF0F1", bd=2, relief="solid")
    dmsg.place(x=180, y=100, width=230)

    Label(t, text="Enter Encryption Key:", font=("Helvetica", 11), fg='white', bg='#2C3E50').place(x=20, y=140)
    key = StringVar()
    dkey = Entry(t, textvariable=key, font=("Helvetica", 11), bg="#ECF0F1", bd=2, relief="solid")
    dkey.place(x=180, y=140, width=230)

    Label(t, text="Logs", font=("Helvetica", 14, "bold"), fg='white', bg='#2C3E50').place(x=20, y=180)
    
    text_area = scrolledtext.ScrolledText(t, wrap="word", width=47, height=6, font=("Times New Roman", 12), bg="#ECF0F1", bd=2)
    text_area.place(x=20, y=220)
    text_area.configure(state='disabled')

    button_style = {'fg': 'white', 'bg': '#2980B9', 'font': ('Helvetica', 12, 'bold')}
    Button(t, text="Send", command=lambda: send_func(dip.get(), dmsg, dkey.get(), text_area, myip, interface), **button_style).place(x=130, y=360, width=80)
    Button(t, text="Exit", command=lambda: destroy(t), **button_style).place(x=220, y=360, width=80)

    t.mainloop()

def rec_func(password,target_ip,text_area,interface,myip):
    reciever_main(password,target_ip,text_area,interface,myip)
    
def stop_sniff():
    stop_event.set()
    delete_firewall_rule()
    print("Sniffing Stopped From Button!")


def recieve_window():
    t = Toplevel()
    t.resizable(0, 0)
    t.geometry("430x400")
    t.title("Receive Your Message")
    t.configure(bg="mediumseagreen")  

    Label(t, text="IPv6 Hidden Message Receiver", font=("Helvetica", 15, "bold"), fg='white', bg='seagreen', pady=10).pack(fill="x")
    
    Label(t, text="Enter Source IPv6:", font=("Helvetica", 11), fg='white', bg='mediumseagreen').place(x=20, y=60)
    ip = StringVar()
    dip = Entry(t, textvariable=ip, font=("Helvetica", 11), bg="#ECF0F1", bd=0, relief="solid")
    dip.place(x=180, y=60, width=230)

    Label(t, text="Enter Decryption Key:", font=("Helvetica", 11), fg='white', bg='mediumseagreen').place(x=20, y=100)
    key = StringVar()
    dkey = Entry(t, textvariable=key, font=("Helvetica", 11), bg="#ECF0F1", bd=0, relief="solid")
    dkey.place(x=180, y=100, width=230)

    Label(t, text="Received Packet Logs", font=("Helvetica", 14, "bold"), fg='white', bg='mediumseagreen').place(x=20, y=140)
    
    text_area = scrolledtext.ScrolledText(t, wrap="word", width=47, height=8, font=("Times New Roman", 12), bg="#ECF0F1", bd=2)
    text_area.place(x=20, y=180)
    text_area.configure(state='disabled')

    button_style = {'fg': 'white', 'bg': 'seagreen', 'font': ('Helvetica', 12, 'bold')}
    Button(t, text="Start", command=lambda: rec_func(key.get(), ip.get(), text_area, interface, myip), **button_style).place(x=75, y=360, width=80)
    Button(t, text="Exit", command=lambda: destroy_receiver(t), **button_style).place(x=165, y=360, width=80)
    Button(t, text="Stop Receiving", command=stop_sniff, **button_style).place(x=255, y=360, width=125)

    t.mainloop()


def main():
    global myip, interface
    myip = "::1"
    parser = argparse.ArgumentParser(description="Send IPv6 packets to a specified destination.")
    # parser.add_argument("src_ip", help="The source IPv6 address.")
    parser.add_argument("interface", help="The Newtork interface to send and sniff packets on.")
    args = parser.parse_args() 
    # myip = args.src_ip
    interface = args.interface

    #fetch user ip through powershell
    src_ip_process = subprocess.run("powershell -encoded KABHAGUAdAAtAE4AZQB0AEkAUABBAGQAZAByAGUAcwBzACAALQBBAGQAZAByAGUAcwBzAEYAYQBtAGkAbAB5ACAASQBQAHYANgAgAHwAIABXAGgAZQByAGUALQBPAGIAagBlAGMAdAAgAHsAIAAkAF8ALgBQAHIAZQBmAGkAeABPAHIAaQBnAGkAbgAgAC0AZQBxACAAJwBSAG8AdQB0AGUAcgBBAGQAdgBlAHIAdABpAHMAZQBtAGUAbgB0ACcAIAAtAGEAbgBkACAAJABfAC4AUwB1AGYAZgBpAHgATwByAGkAZwBpAG4AIAAtAGUAcQAgACcAUgBhAG4AZABvAG0AJwAgAC0AYQBuAGQAIAAkAF8ALgBBAGQAZAByAGUAcwBzAFMAdABhAHQAZQAgAC0AZQBxACAAJwBQAHIAZQBmAGUAcgByAGUAZAAnACAAfQApAC4ASQBQAEEAZABkAHIAZQBzAHMA".split(),stdout=subprocess.PIPE)
    dirty_src_ip = str(src_ip_process.stdout.decode())
    src_ip = dirty_src_ip[:-2]
    myip = src_ip

    t = Tk()
    t.title("Start-Up Window")
    t.geometry("370x270")
    t.resizable(0, 0)
    t.configure(bg="grey25")

    Label(t, text="Welcome to IPv6 Steganography!", font=("Helvetica", 16, "bold"), fg='white', bg='grey30', pady=10).pack(fill="x")

    Label(t, text="Choose whether to send or receive!", font=("Helvetica", 13, "bold","underline"), fg='white', bg='grey25').place(x=35, y=60)

    button_style = {'fg': 'white', 'bg': '#8E44AD', 'font': ('Helvetica', 12, 'bold')}
    Button(t, text="Send Message", command=send_window, **button_style).place(x=120, y=100, width=120)
    Button(t, text="Receive Message", command=recieve_window, **button_style).place(x=110, y=145, width=140)
    Button(t, text="Exit", command=lambda: destroy_all(t), fg='white', bg='#E74C3C', font=('Helvetica', 12, 'bold')).place(x=140, y=190, width=80)

    t.mainloop()


try : 
    main()
except KeyboardInterrupt: 
    exit()
    print("Closed")