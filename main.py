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
    subprocess.run('taskkill /f /im python.exe')

def send_func(ip,msg,key,scroll,myip,interface):
    val = msg.get()
    msg.clipboard_clear()
    sender_main(ip,val,key,scroll,myip,interface)

def send_window():
    t=Toplevel()
    t.resizable(0,0)
    t.geometry("400x380")
    t.title("Send Your Message")
    t.configure(bg="grey")
    Label(t,text="Welcome to IPv6 Hidden message sender!",font="arial 15 bold",fg='white',bg='brown').place(x=0,y=0)
    yc=90
    Label(t,text="Enter Destination IPv6: ").place(x=10,y=50)
    Label(t,text="Enter your message: ").place(x=10,y=80)
    Label(t,text="Enter encryption key: ").place(x=10,y=110)
    ip=StringVar()
    msg=StringVar()
    key=StringVar()
    dip=Entry(t,textvariable=ip)
    dmsg=Entry(t,textvariable=msg)
    dkey=Entry(t,textvariable=key)
    dip.place(x=150,y=50)
    dmsg.place(x=150,y=80)
    dkey.place(x=150,y=110)
    text_area = scrolledtext.ScrolledText(t,  
            wrap = WORD,  
            width = 35,  
            height = 6,  
            font = ("Times New Roman", 15)
            )
    Label(t,text="Logs",font="arial 15 bold",fg='white',bg='black').place(x=10,y=175)
    text_area.place(x=10,y=205)
    
    text_area.configure(state ='disabled')
    Button(t,text="Send.",fg='lime',bg='black',command=lambda:send_func(dip.get(),dmsg,dkey.get(),text_area,myip,interface)).place(x=150,y=140)
    Button(t,text="Exit.",fg='lime',bg='black',command=lambda:destroy(t)).place(x=200,y=140)
    t.mainloop()


def rec_func(password,target_ip,text_area,interface,myip):
    reciever_main(password,target_ip,text_area,interface,myip)
    
def stop_sniff():
    stop_event.set()
    delete_firewall_rule()
    print("Sniffing Stopped From Button!")


def recieve_window():
    t=Toplevel()
    t.resizable(0,0)
    t.geometry("400x380")
    t.title("Receive Your Message")
    t.configure(bg="grey")
    Label(t,text="Welcome to IPv6 Hidden message receiver!",font="arial 15 bold",fg='white',bg='brown').place(x=0,y=0)
    yc=90
    Label(t,text="Enter Source IPv6: ").place(x=10,y=50)
    Label(t,text="Enter Decryption Key: ").place(x=10,y=80)
    ip=StringVar()
    key=StringVar()
    dip=Entry(t,textvariable=ip)
    dkey=Entry(t,textvariable=key)
    dip.place(x=150,y=50)
    dkey.place(x=150,y=80)
    text_area = scrolledtext.ScrolledText(t,  
            wrap = WORD,  
            width = 35,  
            height = 6,  
            font = ("Times New Roman", 15)
            )
    Label(t,text="Recieved Packet Logs",font="arial 15 bold",fg='white',bg='grey').place(x=10,y=150)
    text_area.place(x=10,y=190)
    
    text_area.configure(state ='disabled')
    Button(t,text="Start.",fg='lime',bg='black',command=lambda:rec_func(key.get(),ip.get(),text_area,interface,myip)).place(x=90,y=120)
    Button(t,text="Exit.",fg='lime',bg='black',command=lambda:destroy_receiver(t)).place(x=140,y=120)
    Button(t,text="Stop Recieving.",fg='lime',bg='black',command=stop_sniff).place(x=180,y=120)
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

    t=Tk()
    t.title("Start-Up Window")
    t.geometry("370x270")
    t.resizable(0,0)
    Label(t,text="Welcome to IPv6 Steganography!",font="arial 16 bold",fg='white',bg='brown').place(x=10,y=0)
    Label(t,text="Choose whether to send or receive!",font="arial 13 bold",fg='white',bg='green').place(x=35,y=40)

    Button(t,text="Send Message",border=5,fg="white",bg="purple",command=send_window).place(x=55,y=120)
    Button(t,text="Recieve Message",border=5,fg="white",bg="purple",command=recieve_window).place(x=155,y=120)
    Button(t,text="Exit",fg='white',bg='purple',command=lambda:destroy_all(t),border=5).place(x=265,y=120)
    t.mainloop()


try : 
    main()
except KeyboardInterrupt: 
    exit()
    print("Closed")