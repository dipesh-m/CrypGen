#External libraries to install are pyperclip and zxcvbn

import random
from random import randint
import tkinter as Tk
from zxcvbn import zxcvbn
import pyperclip
import ctypes
from pathlib import Path
import pathlib
import re
import sys
import os

#setting taskbar icon

ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('CrypGen')

#Functions to avoid blurred texts (DPI PROBLEM)     Source:- https://stackoverflow.com/questions/41315873/attempting-to-resolve-blurred-tkinter-text-scaling-on-windows-10-high-dpi-disp

def Get_HWND_DPI(window_handle):
    #To detect high DPI displays and avoid need to set Windows compatibility flags
    import os
    if os.name == "nt":
        from ctypes import windll, pointer, wintypes
        try:
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        DPI100pc = 96  # DPI 96 is 100% scaling
        DPI_type = 0  # MDT_EFFECTIVE_DPI = 0, MDT_ANGULAR_DPI = 1, MDT_RAW_DPI = 2
        winH = wintypes.HWND(window_handle)
        monitorhandle = windll.user32.MonitorFromWindow(winH, wintypes.DWORD(2))  # MONITOR_DEFAULTTONEAREST = 2
        X = wintypes.UINT()
        Y = wintypes.UINT()
        try:
            windll.shcore.GetDpiForMonitor(monitorhandle, DPI_type, pointer(X), pointer(Y))
            return X.value, Y.value, (X.value + Y.value) / (2 * DPI100pc)
        except Exception:
            return 96, 96, 1  # Assume standard Windows DPI & scaling
    else:
        return None, None, 1

def TkGeometryScale(s, cvtfunc):
    patt = r"(?P<W>\d+)x(?P<H>\d+)\+(?P<X>\d+)\+(?P<Y>\d+)"  # format "WxH+X+Y"
    R = re.compile(patt).search(s)
    G = str(cvtfunc(R.group("W"))) + "x"
    G += str(cvtfunc(R.group("H"))) + "+"
    G += str(cvtfunc(R.group("X"))) + "+"
    G += str(cvtfunc(R.group("Y")))
    return G

def MakeTkDPIAware(TKGUI):
    TKGUI.DPI_X, TKGUI.DPI_Y, TKGUI.DPI_scaling = Get_HWND_DPI(TKGUI.winfo_id())
    TKGUI.TkScale = lambda v: int(float(v) * TKGUI.DPI_scaling)
    TKGUI.TkGeometryScale = lambda s: TkGeometryScale(s, TKGUI.TkScale)

#functions for navigation

def back_to_main_page():
    button_main['state']="disabled"
    page_main.tkraise()

def bring_up(frame):
    frame.tkraise()
    button_main['state']="normal"

#functions for generating random passwords

def disabler_on_error():
    score_answer['text']=""
    pass_listbox.delete(0, Tk.END)
    button2['state'] = "disabled"
    button3['state']="disabled"

def error_for_gen():
    global no_of_pass_str
    no_of_pass_str=number_entry.get()
    global no_of_pass_int
    if(no_of_pass_str.isdigit()):
        no_of_pass_int=int(no_of_pass_str)
    global no_of_pass_bool

    global pass_length_str
    pass_length_str=length_entry.get()
    global pass_length_int
    if(pass_length_str.isdigit()):
        pass_length_int=int(pass_length_str)
    global pass_length_bool

    if(no_of_pass_str.isdigit() and no_of_pass_int >= 1 and no_of_pass_int <=50):
        no_of_pass_bool=1
    else:
        no_of_pass_bool = 0
        error['text']="ERROR: Please enter a value from 1-50 in Field 1"
        disabler_on_error()
        return

    if(no_of_pass_bool==1 and pass_length_str.isdigit() and pass_length_int >= 1 and pass_length_int <=256):
        pass_length_bool=1
    else:
        pass_length_bool = 0
        error['text']="ERROR: Please enter a value from 1-256 in Field 2"
        disabler_on_error()
        return

    if(no_of_pass_bool==1 and pass_length_bool==1 and var1.get()==0 and var2.get()==0 and var3.get()==0 and var4.get()==0):
        error['text']="ERROR: You must select at least one character set"
        disabler_on_error()
        return

    generate()
    error['text']=""

def scoreOfSelected(evt):
    get_s=zxcvbn(pass_listbox.get(pass_listbox.curselection()))
    if(get_s['score']==0 or get_s['score']==1 or get_s['score']==2):
        score_answer['text']="WEAK"
        score_answer.configure(fg='red')
    elif(get_s['score']==3):
        score_answer['text']="MODERATE"
        score_answer.configure(fg='blue')
    else:
        score_answer['text']="STRONG"
        score_answer.configure(fg='green')

def copy_clipboard():
    global copy_this
    copy_this=pass_listbox.get(pass_listbox.curselection())
    root.clipboard_clear()
    pyperclip.copy(copy_this)
    pyperclip.paste()
    root.update()

def generate():
    symbol_bool=0
    number_bool=0
    lowercase_bool=0
    uppercase_bool=0

    if(var1.get()==1):
        chars='!@#$%^&*-_=+?'
        symbol_bool=1
    elif(var2.get()==1):
        chars='0123456789'
        number_bool=1
    elif(var3.get()==1):
        chars='abcdefghijklmnopqrstuvwxyz'
        lowercase_bool=1
    elif(var4.get()==1):
        chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        uppercase_bool=1

    if(var1.get()==1 and symbol_bool==0):
        chars+='!@#$%^&*`~-_=+()[]{}\|;:,<.>/?\'\"'

    if(var2.get()==1 and number_bool==0):
        chars+='0123456789'

    if(var3.get()==1 and lowercase_bool==0):
        chars+='abcdefghijklmnopqrstuvwxyz'

    if(var4.get()==1 and uppercase_bool==0):
        chars+='ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    if(var5.get()==0 and symbol_bool==1):
        chars+='(){}[]|`/\~,.;:<>\'\"'

    global password
    password=[]
    for d in range(no_of_pass_int):
        pass_element=''
        for c in range(pass_length_int):
            pass_element+=random.choice(chars)
        password.append(pass_element)

    pass_listbox.delete(0, Tk.END)

    for e in range(no_of_pass_int):
        pass_listbox.insert(no_of_pass_int, password[e])
    pass_listbox.select_set(0)

    get_s=zxcvbn(password[0])
    if(get_s['score']==0 or get_s['score']==1 or get_s['score']==2):
        score_answer['text']="WEAK"
        score_answer.configure(fg='red')
    elif(get_s['score']==3):
        score_answer['text']="MODERATE"
        score_answer.configure(fg='blue')
    else:
        score_answer['text']="STRONG"
        score_answer.configure(fg='green')

    button2['state'] = "normal"
    button3['state']="normal"

def on_closing_report():
    button2['state'] = "normal"
    rep.destroy()

def report():
    global rep
    rep=Tk.Toplevel(root)
    rep.iconbitmap(ICON_PATH)
    rep.resizable(0,0)
    rep.configure(bg='white')

    button2['state'] = "disabled"

    for_this_pass=pass_listbox.get(pass_listbox.curselection())
    make_the_report=zxcvbn(for_this_pass)

    the_password=Tk.Label(rep, bg='white', text="\nPASSWORD :   " + make_the_report['password'] + "\n", font=("Calibri", 14))
    the_password.pack(fill=Tk.BOTH)

    the_score=Tk.Label(rep, bg='white', text="                                          SCORE(0-4) :   " + str(make_the_report['score']) + "              (0 being worst score in terms of strength)" + "\n", font=("Calibri", 14))
    the_score.pack()

    the_guesses=Tk.Label(rep, bg='white', text="GUESSES :   " + str(make_the_report['guesses']) + "\n", font=("Calibri", 14))
    the_guesses.pack(fill=Tk.BOTH)

    the_pass_crack_time=Tk.Label(rep, bg='white', text="PASSWORD CRACK TIME :   " + str(make_the_report['crack_times_display']['online_no_throttling_10_per_second']) + "          (unthrottled online attack, 10/s)" + "\n", font=("Calibri", 14))
    the_pass_crack_time.pack(fill=Tk.BOTH)

    the_pass_crack_time1=Tk.Label(rep, bg='white', text="               PASSWORD CRACK TIME :   " + str(make_the_report['crack_times_display']['offline_slow_hashing_1e4_per_second']) + "             (offline attack, slow hash, many cores, 10k/s)" + "\n", font=("Calibri", 14))
    the_pass_crack_time1.pack(fill=Tk.BOTH)

    the_pattern=Tk.Label(rep, bg='white', text="PATTERN :   " + make_the_report['sequence'][0]['pattern'] + "\n", font=("Calibri", 14))
    the_pattern.pack(fill=Tk.BOTH)

    if(make_the_report['feedback']['warning'] != ''):
        the_warning=Tk.Label(rep, bg='white', text="WARNING :   " + make_the_report['feedback']['warning'] + "\n", font=("Calibri", 14))
        the_warning.pack(fill=Tk.BOTH)

    if(make_the_report['feedback']['suggestions'] != []):
        the_suggestions=Tk.Label(rep, bg='white', text="SUGGESTIONS :   " + str(make_the_report['feedback']['suggestions']) + "\n", font=("Calibri", 14))
        the_suggestions.pack(fill=Tk.BOTH)

    rep.protocol("WM_DELETE_WINDOW", on_closing_report)

#function for checking password strength

def check():
    see_the_pass_str=str(see_the_pass.get())
    if(see_the_pass_str=='' or len(see_the_pass_str)>40):
        error_empty['text']="ERROR: Please enter a password of length 1-40"

        for_check_password['text']=""
        for_color_password['text']=""
        for_check_score['text']=""
        for_check_guesses['text']=""
        for_check_pass_crack_time['text']=""
        addition_for_check_pass_crack_time['text']=""
        for_check_pass_crack_time1['text']=""
        addition_for_check_pass_crack_time1['text']=""
        for_check_pattern['text']=""
        for_check_dict_name['text']=""
        for_check_suggestions['text']=""
        for_check_warning['text']=""

        return
    else:
        error_empty['text']=""

        make_the_report=zxcvbn(see_the_pass_str)

        for_check_password['text']="PASSWORD :  " + make_the_report['password']
        for_check_score['text']="SCORE(0-4) :  " + str(make_the_report['score'])
        if(make_the_report['score']==0 or make_the_report['score']==1 or make_the_report['score']==2):
            for_color_password['text']="WEAK"
            for_color_password.configure(fg='red')
        elif(make_the_report['score']==3):
            for_color_password['text']="MODERATE"
            for_color_password.configure(fg='blue')
        else:
            for_color_password['text']="STRONG"
            for_color_password.configure(fg='green')
        for_check_guesses['text']="GUESSES :  " + str(make_the_report['guesses'])
        for_check_pass_crack_time['text']="PASSWORD CRACK TIME :  " + str(make_the_report['crack_times_display']['online_no_throttling_10_per_second'])
        addition_for_check_pass_crack_time['text']="(unthrottled online attack, 10/s)"
        for_check_pass_crack_time1['text']="PASSWORD CRACK TIME :  " + str(make_the_report['crack_times_display']['offline_slow_hashing_1e4_per_second'])
        addition_for_check_pass_crack_time1['text']="(offline attack, slow hash, many cores, 10k/s)"
        for_check_pattern['text']="PATTERN :  " + make_the_report['sequence'][0]['pattern']
        if(any('dictionary_name' in xx for xx in make_the_report['sequence'])):
            found=next(i for i,d in enumerate(make_the_report['sequence']) if 'dictionary_name' in d)
            for_check_dict_name['text']="DICTIONARY NAME:  " + make_the_report['sequence'][found]['dictionary_name']
        else:
            for_check_dict_name['text']=""
        suggestion_length=(len(make_the_report['feedback']['suggestions']))
        if(suggestion_length>1):
            for_check_suggestions['text']="SUGGESTIONS : " + str(make_the_report['feedback']['suggestions'][1])
        elif(suggestion_length==1):
            for_check_suggestions['text']="SUGGESTIONS : " + str(make_the_report['feedback']['suggestions'][0])
        else:
            for_check_suggestions['text']=""
        if(make_the_report['feedback']['warning'] != ''):
            for_check_warning['text']="WARNING : " + make_the_report['feedback']['warning']
        else:
            for_check_warning['text']=""

#functions for encryption and decryption

def generate_otp():
    if(not(ans_mess_length.get()) or int(ans_mess_length.get())<1 or int(ans_mess_length.get())>8000):
        display_otp_status['text']=""
        display_otp_status['text']="ERROR: Enter a value from 1 to \n 8000 in Field 1"
        display_otp_status.configure(fg='red')
    elif(str(ans_name_of_otp_file.get())==""):
        display_otp_status['text']=""
        display_otp_status['text']="ERROR: Enter a suitable filename\nin Field 2"
        display_otp_status.configure(fg='red')
    else:
        file_name="otp" + "-" + str(ans_name_of_otp_file.get())
        if getattr(sys, 'frozen', False):
            of=".\\otp"
            if(os.path.isdir(of)==False):
                os.makedirs(of)
        elif __file__:
            dir=str(pathlib.Path(__file__).parent.absolute())
            off=dir + "\\otp"
            if(os.path.isdir(off)==False):
                os.makedirs(off)

        otp_folder=Path("otp/")
        if getattr(sys, 'frozen', False):
            otp_file=otp_folder/file_name
        elif __file__:
            dir=pathlib.Path(__file__).parent.absolute()
            otp_file=dir/otp_folder/file_name

        if(otp_file.is_file()):
            display_otp_status['text']=""
            display_otp_status['text']="FAILURE. OTP File already exists. Please\nchoose a different filename or\ndelete the existing file"
            display_otp_status.configure(fg='red')
        else:
            with open(otp_file, "w") as f:
                for i in range(int(ans_mess_length.get())):
                    f.write(str(randint(0,26)) + "\n")

            display_otp_status['text']=""
            display_otp_status['text']="SUCCESS. Check 'otp' Folder \n for the OTP File Generated"
            display_otp_status.configure(fg='green')

def load_sheet(filename):
    with open(filename, "r") as f:
        contents_of_sheet=f.read().splitlines()
    return contents_of_sheet

def save_encrypted_file(ciphertext, save_here):
    with open(save_here, "w") as f:
        f.write(ciphertext)

def clear():
    ans_the_plain_text.delete("1.0", Tk.END)

def encrypt():
    if(str(ans_otp_file_for_encryp.get())==""):
        display_encrypt_status['text']=""
        display_encrypt_status['text']="ERROR: Enter the name of OTP \n File in Field 1"
        display_encrypt_status.configure(fg='red')
    elif(str(ans_save_encryp_file.get())==""):
        display_encrypt_status['text']=""
        display_encrypt_status['text']="ERROR: Enter the name of the \n encrypted File in Field 2"
        display_encrypt_status.configure(fg='red')
    elif(str(ans_the_plain_text.get("1.0", "end-1c"))==""):
        display_encrypt_status['text']=""
        display_encrypt_status['text']="ERROR: Enter the message to be \n encrypted in Field 3"
        display_encrypt_status.configure(fg='red')
    else:
        if getattr(sys, 'frozen', False):
            of=".\\encrypted"
            if(os.path.isdir(of)==False):
                os.makedirs(of)
        elif __file__:
            dir=str(pathlib.Path(__file__).parent.absolute())
            off=dir + "\\encrypted"
            if(os.path.isdir(off)==False):
                os.makedirs(off)
        oenc_filename=str(ans_otp_file_for_encryp.get())
        oenc_folder=Path("otp/")
        if getattr(sys, 'frozen', False):
            oenc_file=oenc_folder/oenc_filename
        elif __file__:
            dir=pathlib.Path(__file__).parent.absolute()
            oenc_file=dir/oenc_folder/oenc_filename

        if(oenc_file.is_file()==False):
            display_encrypt_status['text']=""
            display_encrypt_status['text']="ERROR: OTP File specified in \n Field 1 does not exist"
            display_encrypt_status.configure(fg='red')
        else:
            enc_save_file_name=str(ans_save_encryp_file.get())
            enc_save_folder=Path("encrypted/")
            if getattr(sys, 'frozen', False):
                enc_save_file=enc_save_folder/enc_save_file_name
            elif __file__:
                dir=pathlib.Path(__file__).parent.absolute()
                enc_save_file=dir/enc_save_folder/enc_save_file_name

            if(enc_save_file.is_file()):
                display_encrypt_status['text']=""
                display_encrypt_status['text']="FAILURE. Encrypted File already\nexists. Please choose a different\nfilename or delete the existing file"
                display_encrypt_status.configure(fg='red')
            else:
                encrypt_sheet_contents=load_sheet(oenc_file)
                ciphertext=""
                l_plain=str(ans_the_plain_text.get("1.0", "end-1c")).lower()
                for position, character in enumerate(l_plain):
                    if(character not in ALPHABET):
                        ciphertext+=character
                    else:
                        encrypted=(ALPHABET.index(character) + int(encrypt_sheet_contents[position]))%26
                        ciphertext+=ALPHABET[encrypted]

                display_encrypt_status['text']=""
                display_encrypt_status['text']="SUCCESS. Check 'encrypted'\n  Folder for the\n  Encrypted File Generated"
                display_encrypt_status.configure(fg='green')

                save_encrypted_file(ciphertext, enc_save_file)

def load_file(filename):
    with open(filename, "r") as f:
        contents_of_file=f.read()
    return contents_of_file.lower()

def on_closing_show():
    button7['state']="normal"
    show.destroy()

def decrypt():
    if(str(ans_otp_file_for_decryp.get())==""):
        display_decrypt_status['text']=""
        display_decrypt_status['text']="ERROR: Enter the name of OTP \n File in Field 1"
        display_decrypt_status.configure(fg='red')
    elif(str(ans_decryp_file.get())==""):
        display_decrypt_status['text']=""
        display_decrypt_status['text']="ERROR: Enter the name of the \n encrypted file in Field 2"
        display_decrypt_status.configure(fg='red')
    else:
        odec_filename=str(ans_otp_file_for_decryp.get())
        odec_folder=Path("otp/")
        if getattr(sys, 'frozen', False):
            odec_file=odec_folder/odec_filename
        elif __file__:
            dir=pathlib.Path(__file__).parent.absolute()
            odec_file=dir/odec_folder/odec_filename

        edec_filename=str(ans_decryp_file.get())
        edec_folder=Path("encrypted/")
        if getattr(sys, 'frozen', False):
            edec_file=edec_folder/edec_filename
        elif __file__:
            dir=pathlib.Path(__file__).parent.absolute()
            edec_file=dir/edec_folder/edec_filename

        if(odec_file.is_file()==False):
            display_decrypt_status['text']=""
            display_decrypt_status['text']="ERROR: OTP File specified in \n Field 1 does not exist"
            display_decrypt_status.configure(fg='red')
        elif(edec_file.is_file()==False):
            display_decrypt_status['text']=""
            display_decrypt_status['text']="ERROR: Encrypted File specified in \n Field 2 does not exist"
            display_decrypt_status.configure(fg='red')
        else:
            decrypt_sheet_contents=load_sheet(odec_file)
            decrypt_file_contents=load_file(edec_file)
            display_decrypt_status['text']=""
            button7['state'] = "disabled"

            decrypted_text=""
            for position, character in enumerate(decrypt_file_contents):
                if(character not in ALPHABET):
                    decrypted_text+=character
                else:
                    decrypted=(ALPHABET.index(character) - int(decrypt_sheet_contents[position]))%26
                    decrypted_text+=ALPHABET[decrypted]

            global show
            show=Tk.Toplevel(page3, bg='white')
            show.iconbitmap(ICON_PATH)
            show.geometry("410x300")
            show.resizable(0,0)
            show.configure(bg='white')

            canvas = Tk.Canvas(show, bg='white')
            scroll4 = Tk.Scrollbar(show, orient="vertical", command=canvas.yview)

            show_frame=Tk.Frame(canvas, width=410, height=300, bg='white')

            show_decrypted_text=Tk.Text(show_frame, width=48, height=20, highlightthickness=0, bg='white', highlightbackground='white smoke', yscrollcommand=scroll4.set, font=("Calibri", 14))
            show_decrypted_text.insert(1.0, decrypted_text)
            show_decrypted_text.pack()

            canvas.create_window(0, 0, anchor='nw', window=show_frame)
            canvas.update_idletasks()

            canvas.configure(scrollregion=canvas.bbox('all'), yscrollcommand=scroll4.set)
            canvas.pack(fill='both', expand=True, side='left')
            scroll4.pack(fill='y', side='right')

            show.protocol("WM_DELETE_WINDOW", on_closing_show)

#Main Window:

root=Tk.Tk()
MakeTkDPIAware(root)  # Sets the windows flag + gets adds .DPI_scaling property
root.geometry(root.TkGeometryScale("634x730+450+20"))
root.resizable(0, 0)
root.config(bg='white')
root.title('CrypGen')

global ICON_PATH
global LOGO_PATH
if getattr(sys, 'frozen', False):
    ICON_PATH=".\\img\\icon.ico"
    LOGO_PATH=".\\img\\logo.png"
elif __file__:
    dir=str(pathlib.Path(__file__).parent.absolute())
    ICON_PATH=dir + "\\img\\icon.ico"
    LOGO_PATH=dir + "\\img\\logo.png"

root.iconbitmap(ICON_PATH)

icon=Tk.PhotoImage(file = LOGO_PATH)
icon_label=Tk.Label(root, image=icon, bg='white')
icon_label.place(x=295)

page_main=Tk.Frame(root, width=790, height=760, bg='white')
page_main.place(x=0, y=150)

msg_text1="CrypGen provides 3 features :- \n- PASSWORD GENERATION: You can generate passwords containing randomized characters which are\n   very hard to break. Also, with the help of 'zxcvbn' library by DropBox, you can also generate a strength\n   report of the passwords generated. Options to include or exclude special characters, numbers, etc. are\n   also available. PLEASE NOTE: Max. Password Length Supported is 256 and Max. Password Generations\n   is limited to 50. GENERATING TOO MANY LENGTHY PASSWORDS MAY CAUSE THE PROGRAM TO SLOW\n   DOWN OR CRASH."
msg1=Tk.Message(page_main, text=msg_text1, width=790, bg='white', font=("Calibri", 13))
msg1.place(x=25, y=0)

msg_text2="- PASSWORD STRENGTH CHECKING: A general-use password strength checker where you can enter any\n   password (or any string) and it will generate a strength report of that password with details like time\n   and guesses required to crack the password, matching patterns found, etc. Additionally, it may also\n   provide suggestions and warnings about the password. It uses the 'zxcvbn' library by DropBox which\n   to check the strength of the password."
msg2=Tk.Message(page_main, text=msg_text2, width=790, bg='white', font=("Calibri", 13))
msg2.place(x=25, y=195)

msg_text3="- MESSAGE ENCRYPTION AND DECRYPTION: A simple encryption techinque called as One-Time Pads is\n   used by CrypGen to encrypt any provided message.\n   Steps for encrypting and decrypting a message:-\n   1.) First, generate a One Time Pad which is just a string of random numbers that will be used to encrypt\n   a message. REMEMBER that the OTP used to encrypt a message is the OTP that will be used to decrypt\n   this message. All generated OTPs are stored in folder named 'otp' in the format: otp-<filename-provided>\n   2.) Enter your message that has to be encrypted. Also, provide the otp file name that will be used to\n   encrypt this message. The message is stored in encrypted format as a file in folder 'encrypted' with the\n   name provided for the file.\n   3.) To decrypt an encrypted file, provide the encrypted file name along with the OTP file name that was\n   used to encrypt this file because that same OTP is used only to decrypt the file. NOTE that the file to be\n   decrypted MUST be present in folder 'encrypted'.\n\n   So, as long as only you have access to the OTP files, no one can decipher the contents of any encrypted\n   file. Only way to decipher the contents of encrypted file is to decrypt it in CrypGen using only the same\n   OTP that was used to encrypt it."
msg3=Tk.Message(page_main, text=msg_text3, width=790, bg='white', font=("Calibri", 13))
msg3.place(x=25, y=370)

#Widgets for Generating Random Passwords:

page1=Tk.Frame(root, width=790, height=760, bg='white')
page1.place(x=0, y=150)

gen_pass=Tk.Label(page1, text='GENERATE RANDOM PASSWORDS', bg='white', font=("Calibri", 18))
gen_pass.place(x=225, y=10)

number=Tk.Label(page1, text="1. Number of Passwords:", bg='white', font=("Calibri", 14))
number.place(x=110, y=50)
number_entry=Tk.Entry(page1, width=20, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
number_entry.insert(Tk.END, '1')
number_entry.place(x=395, y=50)

length=Tk.Label(page1, text="2. Password Length:", bg='white', font=("Calibri", 14))
length.place(x=110, y=90)
length_entry=Tk.Entry(page1, width=20, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
length_entry.insert(Tk.END, '15')
length_entry.place(x=395, y=90)

i_symbols=Tk.Label(page1, text="3. Include Symbols:", bg='white', font=("Calibri", 14))
i_symbols.place(x=110, y=130)
var1=Tk.IntVar()
i_symbols_check=Tk.Checkbutton(page1, text="(e.g. !@#$)", variable=var1, bg='white', font=("Calibri", 14))
i_symbols_check.place(x=390, y=130)
i_symbols_check.select()

i_numbers=Tk.Label(page1, text="4. Include Numbers:", bg='white', font=("Calibri", 14))
i_numbers.place(x=110, y=170)
var2=Tk.IntVar()
i_numbers_check=Tk.Checkbutton(page1, text="(e.g. 1234)", variable=var2, bg='white', font=("Calibri", 14))
i_numbers_check.place(x=390, y=170)
i_numbers_check.select()

i_lowercase=Tk.Label(page1, text="5. Include Lowercase Characters:", bg='white', font=("Calibri", 14))
i_lowercase.place(x=110, y=210)
var3=Tk.IntVar()
i_lowercase_check=Tk.Checkbutton(page1, text="(e.g. abcd)", variable=var3, bg='white', font=("Calibri", 14))
i_lowercase_check.place(x=390, y=210)
i_lowercase_check.select()

i_uppercase=Tk.Label(page1, text="6. Include Uppercase Characters:", bg='white', font=("Calibri", 14))
i_uppercase.place(x=110, y=250)
var4=Tk.IntVar()
i_uppercase_check=Tk.Checkbutton(page1, text="(e.g. ABCD)", variable=var4, bg='white', font=("Calibri", 14))
i_uppercase_check.place(x=390, y=250)
i_uppercase_check.select()

i_ambi=Tk.Label(page1, text="7. Exclude Ambiguous Symbols:", bg='white', font=("Calibri", 14))
i_ambi.place(x=110, y=290)
var5=Tk.IntVar()
i_ambi_check=Tk.Checkbutton(page1, text="((){}[]|`/\~,.;:<>\'\")", variable=var5, bg='white', font=("Calibri", 14))
i_ambi_check.place(x=390, y=290)
i_ambi_check.select()

scroll1=Tk.Scrollbar(page1, orient="vertical")
scroll1.place(x=393 ,y=460, height=171)

scroll2=Tk.Scrollbar(page1, orient="horizontal")
scroll2.place(x=170 ,y=630, width=224)

error=Tk.Label(page1, fg='red', text="               ", bg='white', font=("Calibri", 14))
error.place(x=170, y=400)

pass_listbox=Tk.Listbox(page1, bg='white smoke', height=7, width=22, bd=0.5, yscrollcommand=scroll1.set, xscrollcommand=scroll2.set, font=("Calibri", 14))
pass_listbox.place(x=170, y=460)
scroll1.configure(command=pass_listbox.yview)
scroll2.configure(command=pass_listbox.xview)
pass_listbox.bind('<<ListboxSelect>>', scoreOfSelected)

score=Tk.Label(page1, text="Generated Password's Strength :-", bg='white', font=("Calibri", 14))
score.place(x=455, y=540)

score_answer=Tk.Label(page1, text="         ", bg='white', font=("Calibri", 14))
score_answer.place(x=540, y=570)

#Widgets for Password Strength Checker:-

page2=Tk.Frame(root, width=790, height=760, bg='white')
page2.place(x=0, y=150)

check_pass=Tk.Label(page2, text='CHECK YOUR PASSWORD STRENGTH', bg='white', font=("Calibri", 18))
check_pass.place(x=190, y=10)

enter_pass=Tk.Label(page2, text="Enter Your Password Below :", bg='white', font=("Calibri", 14))
enter_pass.place(x=265, y=60)

see_the_pass=Tk.Entry(page2, width=30, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
see_the_pass.place(x=225, y=100)

error_empty=Tk.Label(page2, text="", fg='red', bg='white', font=("Calibri", 14))
error_empty.place(x=190, y=210)

for_check_password=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_password.place(x=130, y=250)

for_check_score=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_score.place(x=130, y=300)

for_color_password=Tk.Label(page2, text="                     ", bg='white', font=("Calibri", 14))
for_color_password.place(x=270, y=300)

for_check_guesses=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_guesses.place(x=130, y=350)

for_check_pass_crack_time=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_pass_crack_time.place(x=130, y=400)
addition_for_check_pass_crack_time=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
addition_for_check_pass_crack_time.place(x=130, y=430)

for_check_pass_crack_time1=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_pass_crack_time1.place(x=130, y=480)
addition_for_check_pass_crack_time1=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
addition_for_check_pass_crack_time1.place(x=130, y=510)

for_check_pattern=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_pattern.place(x=130, y=560)

for_check_dict_name=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_dict_name.place(x=380, y=560)

for_check_suggestions=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_suggestions.place(x=130, y=610)

for_check_warning=Tk.Label(page2, text="", bg='white', font=("Calibri", 14))
for_check_warning.place(x=130, y=660)

#Widgets for Encryption and Decryption:

ALPHABET='abcdefghijklmnopqrstuvwxyz'

page3=Tk.Frame(root, width=790, height=760, bg='white')
page3.place(x=0, y=150)

enc_mess=Tk.Label(page3, text='CREATE ENCRYPTED MESSAGES', bg='white', font=("Calibri", 18))
enc_mess.place(x=225, y=10)

label_generate_otp=Tk.Label(page3, text="GENERATE A ONE TIME PAD :-", bg='white', font=("Calibri", 14) )
label_generate_otp.place(x=20, y=40)

how_many_sheets=Tk.Label(page3, text="(The OTP generated will be used for encryption and only\nthe same OTP can be used to decrypt that message)", bg='white', font=("Calibri", 14))
how_many_sheets.place(x=20, y=70)

what_mess_length=Tk.Label(page3, text="1.) What will be the maximum message length: ", bg='white', font=("Calibri", 14))
what_mess_length.place(x=20, y=130)
ans_mess_length=Tk.Entry(page3, width=20, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
ans_mess_length.place(x=420, y=130)
ans_mess_length.insert(Tk.END, '2000')

name_of_otp_file=Tk.Label(page3, text="2.) Choose a suitable filename for the OTP File:       \n(e.g. if filename is 'abc', its saved as 'otp-abc')", bg='white', font=("Calibri", 14))
name_of_otp_file.place(x=20, y=170)
ans_name_of_otp_file=Tk.Entry(page3, width=20, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
ans_name_of_otp_file.place(x=420, y=170)

display_otp_status=Tk.Label(page3, text="", bg="white", font=("Calibri", 14))
display_otp_status.place(x=480, y=50)

label_encrypt_message=Tk.Label(page3, text="ENCRYPT A MESSAGE :-", bg='white', font=("Calibri", 14))
label_encrypt_message.place(x=20, y=230)

otp_file_for_encryp=Tk.Label(page3, text="1.) Type the name of the OTP File you want to use: ", bg='white', font=("Calibri", 14))
otp_file_for_encryp.place(x=20, y=260)
ans_otp_file_for_encryp=Tk.Entry(page3, width=20, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
ans_otp_file_for_encryp.place(x=420, y=260)
ans_otp_file_for_encryp.insert(Tk.END, 'otp-')

save_encryp_file=Tk.Label(page3, text="2.) What will be the name of the encrypted file: ", bg='white', font=("Calibri", 14))
save_encryp_file.place(x=20, y=300)
ans_save_encryp_file=Tk.Entry(page3, width=20, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
ans_save_encryp_file.place(x=420, y=300)

scroll3=Tk.Scrollbar(page3, orient="vertical")
scroll3.place(x=502 ,y=370, height=214)

the_plain_text=Tk.Label(page3, text="3.) Type your message below:  (Use lowercase letters)", bg='white', font=("Calibri", 14))
the_plain_text.place(x=20, y=340)
ans_the_plain_text=Tk.Text(page3, width=48, height=9, highlightthickness=1, bg='white', highlightbackground='white smoke', yscrollcommand=scroll3.set, font=("Calibri", 14))
ans_the_plain_text.place(x=18, y=370)
scroll3.configure(command=ans_the_plain_text.yview)

display_encrypt_status=Tk.Label(page3, text="", bg="white", font=("Calibri", 14))
display_encrypt_status.place(x=525, y=370)

label_decrypt_message=Tk.Label(page3, text="DECRYPT A MESSAGE :-", bg='white', font=("Calibri", 14))
label_decrypt_message.place(x=20, y=590)

otp_file_for_decryp=Tk.Label(page3, text="1.) Type the name of the OTP File you want to use: ", bg='white', font=("Calibri", 14))
otp_file_for_decryp.place(x=20, y=620)
ans_otp_file_for_decryp=Tk.Entry(page3, width=20, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
ans_otp_file_for_decryp.place(x=420, y=620)
ans_otp_file_for_decryp.insert(Tk.END, 'otp-')

decryp_file=Tk.Label(page3, text="2.) Type the name of file to be decrypted: ", bg='white', font=("Calibri", 14))
decryp_file.place(x=20, y=660)
ans_decryp_file=Tk.Entry(page3, width=20, highlightthickness=1, bg='white', highlightbackground='white smoke', font=("Calibri", 14))
ans_decryp_file.place(x=420, y=660)

display_decrypt_status=Tk.Label(page3, text="", bg="white", font=("Calibri", 14))
display_decrypt_status.place(x=225, y=700)

#Main Page Buttons

button_main=Tk.Button(root, text='Back To\nMain Page', height=2, state="disabled", command=back_to_main_page, font=("Calibri", 12))
button_main.place(x=30, y=80)

button_go_page1=Tk.Button(page_main, text='GENERATE RANDOM PASSWORDS', height=2, command=lambda: bring_up(page1), font=("Calibri", 12))
button_go_page1.place(x=265, y=140)

button_go_page2=Tk.Button(page_main, text='CHECK YOUR PASSWORD \nSTRENTGH', height=2, command=lambda: bring_up(page2), font=("Calibri", 12))
button_go_page2.place(x=295, y=315)

button_go_page3=Tk.Button(page_main, text='CREATE ENCRYPTED MESSAGES', height=2, command=lambda: bring_up(page3), font=("Calibri", 12))
button_go_page3.place(x=275, y=700)

#Page1 Buttons

button1=Tk.Button(page1, text='GENERATE', height=2, command=error_for_gen, font=("Calibri", 12))
button1.place(x=325, y=340)

button2=Tk.Button(page1, text='Check Full Strength Report of Selected Password', height=2, state="disabled" ,command=report, font=("Calibri", 12))
button2.place(x=170, y=680)

button3=Tk.Button(page1, text='Copy Selected Password', state="disabled", height=2, command=copy_clipboard, font=("Calibri", 12))
button3.place(x=495, y=460)

#Page2 Button

button6=Tk.Button(page2, text='CHECK STRENGTH', height=2, command=check, font=("Calibri", 12))
button6.place(x=305, y=150)

#Page3 Buttons

button4=Tk.Button(page3, text='Generate OTP', height=2, command=generate_otp, font=("Calibri", 12))
button4.place(x=655, y=140)

button5=Tk.Button(page3, text='Encrypt Message', height=2, command=encrypt, font=("Calibri", 12))
button5.place(x=585, y=450)

button8=Tk.Button(page3, text='Clear', command=clear, font=("Calibri", 12))
button8.place(x=624, y=530)

button7=Tk.Button(page3, text='Decrypt File', height=2, command=decrypt, font=("Calibri", 12))
button7.place(x=660, y=630)

#Main Page Loading and mainloop

back_to_main_page()
root.mainloop()