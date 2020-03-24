from Tkinter import *
import tkcalendar as ttkal
import functions_
from tkFileDialog import askopenfilename
from tkFileDialog import askdirectory
from tkFileDialog import asksaveasfilename
import atexit
from datetime import date


class Main_Menu(object):
    def on_click_mm(self,func_arg, key_required):
        try:
            if key_required[0] == False and functions_.key_present()[0] == False:
                canvas0.delete("main_menu")
                func_arg()
        except TypeError:
            popupmsg("ERROR")

        if key_required[0] == True and functions_.key_present()[0] == True:
            canvas0.delete("main_menu")
            self.show = func_arg()
        if key_required[0] == False and functions_.key_present()[0] == True:
            popupmsg("This application only handles one key in the keyring.")
        if key_required[0] == True and functions_.key_present()[0] == False:
            popupmsg("Please import or generate a key before.")
        
    def __init__(self):
        self.button_list = [
        Button(master, text="ENCRYPT / DECRYPT TEXT", command= lambda: self.on_click_mm(Encrypt_Decrypt, [True, False])),
        #Button(master, text="ENCRYPT / DECRYPT FILE", command=),
        #Button(master, text="SIGN", command=),
        #Button(master, text="VERIFY SIGNATURE", command=),
        Button(master, text="IMPORT KEYS", command= lambda: self.on_click_mm(import_keys, [False, False])), 
        Button(master, text="NEW KEYS", command= lambda: self.on_click_mm(new_keys, [False, False]))]

        self.iterator = 200
        for i in self.button_list:
            canvas0.create_window(625, self.iterator, window=i, width = 500, tags="main_menu")
            self.iterator = self.iterator + 50

        self.passph_main_stored = {"passph":None, "is_ok":False}

class Pgp_keys_display():
    def delete_func(self):
        try:
            if functions_.burn_keys():
                pgp_keys_display = Pgp_keys_display()
                main_menu.passph_main_stored = {"passph":None, "is_ok":False}
        except IndexError:
            popupmsg("Please import or generate a key before.")

    def disable_del_but(self):
        canvas0.delete("del_but")
        self.delete_button = Button(master, text="Delete Keys", command=self.delete_func, state=DISABLED)
        canvas0.create_window(300, 40, window=self.delete_button, anchor=NW, width = 90, height=30, tags="del_but")


    def __init__(self):
        try:
            self.pub = str(functions_.gpg.list_keys()[0]["keyid"])
        except IndexError:
            self.pub = "No Imported Public Key"
        try:    
            self.prv = functions_.gpg.list_keys(True)[0]["keyid"]
        except IndexError:
            self.prv = "No Imported Private Key"

        self.public = Label(master, text="Public Key ID : " + self.pub, anchor=W, font="Arial 11")
        self.private = Label(master, text="Private Key ID : " + self.prv, anchor=W, font="Arial 11")
        self.back_to_button = Button(master, text="BACK TO MAIN MENU", command=back_to_main_menu)
        self.save_button = Button(master, text="Save Keys", command=popup_save)
        self.delete_button = Button(master, text="Delete Keys", command=self.delete_func, state=NORMAL)

        canvas0.create_window(10, 10, window=self.public, anchor=NW, width = 1240)
        canvas0.create_window(10, 40, window=self.private, anchor=NW, width = 1240)
        canvas0.create_window(625, 525, window=self.back_to_button, width = 500, height=30)
        canvas0.create_window(300, 10, window=self.save_button, anchor=NW, width = 90, height=30)
        canvas0.create_window(300, 40, window=self.delete_button, anchor=NW, width = 90, height=30, tags="del_but")
        

def import_keys():
    def on_click_ik():
        functions_.import_from_file_name(gui_select_file())
        back_to_main_menu()

    header = Label(master, text="Import one key (.asc file)", font="Arial 11")
    note = Label(master, text="Please note: a public key is generated from an imported private key.", font="Arial 10")
    note2 = Label(master, text="Import only one key (public or private) depending on your need", font="Arial 10")

    button1 = Button(master, text='SELECT KEY', command=on_click_ik)

    canvas0.create_window(625, 150, window=header, width = 500)
    canvas0.create_window(625, 180, window=note, width = 500)
    canvas0.create_window(625, 200, window=note2, width = 500)
    canvas0.create_window(625, 250, window=button1, width = 500)

def gui_select_file():
    filename = askopenfilename(title = "Fichier") # show an "Open" dialog box and return the path to the selected file
    return filename

def back_to_main_menu():
    canvas0.delete("all")
    pgp_keys_display = Pgp_keys_display()
    main_menu = Main_Menu()

def new_keys():
    def on_click_nk():
        def is_valid_expiry_date():
            if expiry.get() == "":
                return False
            if expiry.get() == "0":
                return True
            if expiry.get() == "1" and date_choice.get_date() > date.today():
                return True
            else:
                return False
        def expiry_val():
            if expiry.get() == "0":
                return 0
            if expiry.get() == "1" and date_choice.get_date() > date.today():
                return str(date_choice.get_date())
        if name.get() != "":
            if functions_.is_email(email.get()):
                if length.get() != 0:
                    if is_valid_expiry_date():
                        if passph.get() != "":
                            lp = LoadPage("Generating Key...")
                            lp.show_()
                            master.update()
                            functions_.generate_new_keys(name.get(), email.get(), comment.get(), length.get(), expiry_val(), passph.get())
                            lp.close_()
                            popupmsg("Think about saving your keys before closing \n the program. If you don't, they will be lost forever.")
                            back_to_main_menu()
                        else:
                            popupmsg("Please enter a valid passphrase.")
                    else:
                        popupmsg("Please enter a valid expiry date in the future.")
                else:
                    popupmsg("Please enter a valid key length")
            else:
                popupmsg("Please enter a valid email")              
        else:
            popupmsg("Please enter a valid name")

    master.update() 
    #The application will crash about 25% of the time if master.update() is not present

    length = IntVar(master, 0)
    expiry = StringVar(master, "")

    name_label = Label(master, text="Name :", anchor=W, font="Arial 11")
    name = Entry(master)
    email_label =  Label(master, text="Email :", anchor=W, font="Arial 11")
    email = Entry(master)
    comment_label = Label(master, text="Comment (optional):", anchor=W, font="Arial 11")
    comment = Entry(master)
    length_label = Label(master, text="Key Length :", anchor=W, font="Arial 11")
    length_choice = [Radiobutton(master, text="1024", variable=length, value=1024, indicatoron = 0),
                     Radiobutton(master, text="2048", variable=length, value=2048, indicatoron = 0),
                     Radiobutton(master, text="4096", variable=length, value=4096, indicatoron = 0)]
    expiry_label = Label(master, text="Expiry :", anchor=W, font="Arial 11")
    date_choice = ttkal.DateEntry(master, width=125, background='darkblue', foreground='white', borderwidth=2)
    expiry_choice = [Radiobutton(master, text="NEVER", padx = 20, variable=expiry, value=0, indicatoron = 0),
                     Radiobutton(master, text="ON :", padx = 20, variable=expiry, value=1, indicatoron = 0)]
    passph_label = Label(master, text="Passphrase :", anchor=W, font="Arial 11")
    passph = Entry(master)
    algo_label = Label(master, text="Algorithm : RSA", anchor=W, font="Arial 11")
    
    button1 = Button(master, text='GENERATE KEYS', command=on_click_nk)

    new_key_form = [
    [625, 130, name_label, 500],
    [625, 150, name, 500],
    [625, 180, email_label, 500],
    [625, 200, email, 500],
    [625, 230, comment_label, 500],
    [625, 250, comment, 500],
    [625, 280, length_label, 500],
    [625-166, 300, length_choice[0], 166],    
    [625, 300, length_choice[1], 166],
    [625+166, 300, length_choice[2], 166],
    [625, 330, expiry_label, 500],
    [625-125, 350, expiry_choice[0], 250],
    [625+62, 350, expiry_choice[1], 125],
    [625+62+125, 350, date_choice, 125],
    [625, 380, passph_label, 500],
    [625, 400, passph, 500],
    [625, 430, algo_label, 500],
    [625, 470, button1, 500]]

    for i in new_key_form:
        canvas0.create_window(i[0], i[1], window=i[2], width = i[3], tags="new_key_menu")

class user_entry_popup():
    def __init__(self,msg):        
        self.popup = Toplevel(master)
        self.popup.geometry("500x100") #Width x Height
        self.popup.wm_title("")

        self.label = Label(self.popup, text=msg, font="Arial 11")
        self.label.pack()

        self.mystring = StringVar(self.popup)

        self.user_entry_val = Entry(self.popup, textvariable = self.mystring)
        self.user_entry_val.pack()

        self.B1 = Button(self.popup, text="OKAY", command = self.popup.destroy)
        self.B1.pack()
        #popup.mainloop()
        self.popup.transient(master) #set to be on top of the main window
        self.popup.grab_set() #hijack all commands from the master (clicks on the main window are ignored)
        master.wait_window(self.popup) #pause anything on the main window until this one closes (optional)

        self.value = self.mystring.get()

def popupmsg(msg):
    #master.wait_window()
    popup = Toplevel(master)
    popup.geometry("500x100") #Width x Height
    popup.wm_title("")
    label = Label(popup, text=msg, font="Arial 11")
    label.pack(side="top", fill="x", pady=10)
    B1 = Button(popup, text="OKAY", command = popup.destroy)
    B1.pack()
    #popup.mainloop()
    popup.transient(master) #set to be on top of the main window
    popup.grab_set() #hijack all commands from the master (clicks on the main window are ignored)
    master.wait_window(popup) #pause anything on the main window until this one closes (optional)

def popup_save():
    def pub_save():
        file_path = asksaveasfilename(title = "SAVE KEY",filetypes=[("PGP ASCII Armored File", ".asc")], defaultextension='.asc', initialfile=functions_.get_key_file_name()+"-pub.asc")
        with open(file_path, "w+") as f:
            f.write(functions_.get_key_text(False))
    def sec_save():
        passphee = user_entry_popup("Key Passphrase :").value        
        key_text = functions_.get_key_text(True, passphee)

        if key_text != "":
            file_path = asksaveasfilename(title = "SAVE KEY",filetypes=[("PGP ASCII Armored File", ".asc")], defaultextension='.asc', initialfile=functions_.get_key_file_name()+"-sec.asc")
            with open(file_path, "w+") as f:
                f.write(functions_.get_key_text(True, passphee))
        else:
            popupmsg('Operation failed.')
            
    if functions_.key_present()[0]:
        popup = Toplevel(master)
        popup.wm_title("SAVE KEYS")

        canvas_save = Canvas(popup, width = 700, height = 400)
        canvas_save.pack()

        pub_button = Button(popup, text="SAVE PUBLIC KEY\n\n"+functions_.get_key_file_name()+"-pub.asc", command = pub_save)

        if functions_.key_present()[1]:
            sec_button = Button(popup, text="SAVE PRIVATE KEY\n\n"+functions_.get_key_file_name()+"-sec.asc", command = sec_save)
        else:
            sec_button = Button(popup, text="NO PRIVATE\nKEY",state=DISABLED)

        canvas_save.create_window(200, 200, window=pub_button, width=200, height=200)
        canvas_save.create_window(500, 200, window=sec_button, width=200, height=200)
        
        popup.transient(master) #set to be on top of the main window
        popup.grab_set() #hijack all commands from the master (clicks on the main window are ignored)
        master.wait_window(popup) #pause anything on the main window until this one closes (optional)

    else:
        popupmsg("Please import or generate a key before.")

class Encrypt_Decrypt():
    def dump_Encrypt(self):
        x = self.encrypt_text_box.get("1.0",END).encode('utf-8')
        decrypted_str = functions_.pgp_encrypt(x)
        if decrypted_str.ok:
            if str(self.decrypt_text_box.cget('state')) == "disabled":
                self.decrypt_text_box.configure(state=NORMAL)
                self.decrypt_text_box.delete('1.0', END)
                self.decrypt_text_box.insert(INSERT, decrypted_str.data)
                self.decrypt_text_box.configure(state=DISABLED, bg="#D9D9D9")
            else:
                self.decrypt_text_box.delete('1.0', END)
                self.decrypt_text_box.insert(INSERT, decrypted_str.data)
        else:
            popupmsg("Encryption failed.")
    def dump_Decrypt(self):
        #The user only needs to enter the valid passphrase once.
        #This if statement keeps the user from entering it multiple times 
        if main_menu.passph_main_stored["passph"] != None and main_menu.passph_main_stored["is_ok"]:
            y = main_menu.passph_main_stored["passph"]
        else: 
            y = user_entry_popup("Key Passphrase :").value
            main_menu.passph_main_stored["passph"] = y
            

        lp = LoadPage("Decrypting...")
        lp.show_()
        master.update()
        self.encrypt_text_box.delete('1.0', END)
        x = self.decrypt_text_box.get("1.0",END)
        encrypted_str = functions_.pgp_decrypt(x, y)
        if encrypted_str.ok:
            self.encrypt_text_box.insert(INSERT, encrypted_str.data)
            main_menu.passph_main_stored["is_ok"] = True
        else:
            popupmsg("Decryption failed.")
        lp.close_()

    def __init__(self):
        self.encrypt_text_box = Text(master)
        self.decrypt_text_box = Text(master)

        self.encrypt_button = Button(master, text='>>ENCRYPT>>', command=self.dump_Encrypt)
        self.decrypt_button = Button(master, text='<<DECRYPT<<', command=self.dump_Decrypt)

        self.clear_en_button = Button(master, text='Clear',  command= lambda: self.encrypt_text_box.delete('1.0', END))
        self.clear_de_button = Button(master, text='Clear',  command= lambda: self.decrypt_text_box.delete('1.0', END))

        canvas0.create_window(20, 90, window=self.encrypt_text_box, width=550, height=350, anchor=NW)
        canvas0.create_window(1230, 90, window=self.decrypt_text_box, width=550, height=350, anchor=NE)
        canvas0.create_window(580, 90, window=self.encrypt_button, width=90, height=192, anchor=NW)
        canvas0.create_window(580, 293, window=self.decrypt_button, width=90, height=192, anchor=NW)
        canvas0.create_window(20, 450, window=self.clear_en_button, width=550, height=35, anchor=NW)
        canvas0.create_window(1230, 450, window=self.clear_de_button, width=550, height=35, anchor=NE)

        self.encrypt_text_box.insert(END, "Lorem ipsum...")
        self.decrypt_text_box.insert(END, "-----BEGIN PGP MESSAGE-----")

        if functions_.key_present()[1] == False:
            self.decrypt_text_box.configure(state=DISABLED, bg="#D9D9D9")
            self.decrypt_button.configure(state=DISABLED)
            self.clear_de_button.configure(state=DISABLED)
      
        pgp_keys_display.disable_del_but()


class LoadPage():
    def show_(self):
        self.popup.geometry("500x100") #Width x Height
        self.popup.wm_title("")
        label = Label(self.popup, text=self.text, font="Arial 11")
        label.pack(side="top", fill="x", pady=10)

        self.popup.transient(master) #set to be on top of the main window
        self.popup.grab_set() #hijack all commands from the master (clicks on the main window are ignored)
    def close_(self):
        self.popup.destroy()
    def __init__(self, text):
        self.text = text
        self.popup = Toplevel(master)

atexit.register(functions_.burn_gnugp)
if __name__ == "__main__":
    master = Tk()
    master.title("STEDAP")
    canvas0 = Canvas(master, width = 1250, height = 550)
    canvas0.pack()

    main_menu = Main_Menu()
    pgp_keys_display = Pgp_keys_display()
    
    mainloop()
    #functions.droop_permission()
