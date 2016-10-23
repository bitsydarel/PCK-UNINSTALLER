# -*- coding: utf-8 -*-

from datetime import datetime
from sys import exit, exc_info
from time import sleep, ctime
from threading import Thread
import subprocess as sub
import os
import platform, shutil, re, winreg, wmi, getpass

FORMAT = '%d_%m_%Y_%H_h_%M_min_%S_sec'
FNULL = open(os.devnull, 'w')


def greeting():
    sub.call("cls", shell=True)
    color_white()
    message = print("""##############################################
PCK UNINSTALLER v0.1.4

Author = Darel French Senior Support


1- TO UNINSTALL PCK SOFTWARE

2- EXIT THE PROGRAM

##############################################""")


def goodbye():
    sub.call("color 0f", shell=True)
    clear_func()
    print("""##############################################
              START TIME
                 {0}
               END TIME
                 {1}

                 DONE
                 
        PLEASE REBOOT THE COMPUTER

                  TO

           COMPLETE THE PROCESS

##############################################""".format(start_script, end_script))


def error_printer():
    error_type = exc_info()[0].__name__
    error_file = os.path.basename(exc_info()[2].tb_frame.f_code.co_filename)
    error_line = exc_info()[2].tb_lineno
    print("error type : {0}, on line: {2}".format(error_type, error_line))


def main():
    global start_script, end_script, answer
    reponse = ""
    while reponse != 1 and reponse != 2 :
        try:
            greeting()
            reponse = int(input("\n>> "))
        except ValueError:
            continue

    if reponse == 1:
        try:
            start_script = ctime()
            thread1 = Thread(target=get_software, args=())
            thread2 = Thread(target=remove_files_and_dirs, args=())
            thread3 = Thread(target=delete_scheduled_task, args=())
            thread4 = Thread(target=launch_func, args=())
            thread5 = Thread(target=kill_service_and_process, args=())
            thread6 = Thread(target=delete_register, args=())
            """ REMEMBER TO SPEEED UP THE SID FUNC"""
            pckav_or_pcklive()
            print("\nEtape 2: RESTORE POINT\n")
            restore_point()
            get_users()
            thread1.start()
            print("\nEtape 1: BACKUP REGISTRY\n")
            thread4.start()
            thread3.start()
            clear_func()
            print("\nEtape 3: DELETE SCHEDULED TASK\n")
            clear_func()
            print("\nEtape 4: UNINSTALLING PCK SOFTWARE\n")
            sub.call("taskkill /im explorer.exe /f")
            if answer != 1 and answer != 2:
                try:
                    sub.call('RD /S /Q "{folder}"'.format(folder="{0}\Essentware".format(Program_Files)), shell=True)
                except:
                    pass
            if answer == 1:
                try:
                    sub.call('RD /S /Q "{folder}"'.format(folder="{0}\Essentware\PCKeeper".format(Program_Files)), shell=True)
                except:
                    pass
            if answer == 2:
                try:
                    sub.call('RD /S /Q "{folder}"'.format(folder="{0}\Essentware\PCKAV".format(Program_Files)), shell=True)
                except:
                    pass
            restart_explorer()
            thread5.start()
            thread1.join()
            uninstalling_pck()
            thread2.start()
            thread6.start()
            clear_func()
            print("\nEtape 5: STOP SERVICE AND PROCESS\n")
            kill_service_and_process()
            clear_func()
            print("\nEtape 6: REMOVE DIRS AND FILES\n")
            print("\nEtape 7: REMOVE REGISTRY KEYS AND VALUES\n")
            thread3.join()
            thread2.join()
            thread6.join()
            end_script = ctime()
            goodbye()
            sleep(6)
            main()

        except KeyboardInterrupt:
            sub.call("color 0f", shell=True)
            clear_func()
            exit()

        except SystemExit:
            sub.call("color 0f", shell=True)
            clear_func()
            exit()
        
        except :
            clear_func()
            print("\nThe following error happened \n")
            error_printer()
            exiteur = input("\nCopy the error and email darel@zoomsupport.te.ua\nPress enter to exit")
            sub.call("color 0f", shell=True)
            exit()

    if reponse == 2:
        sub.call("color 0f", shell=True)
        clear_func()
        exit()


def color_white():
    sub.call("color 1F", stderr=sub.PIPE, shell=True)


def clear_func():
    sub.call("cls", stderr=sub.PIPE, shell=True)


def pckav_or_pcklive():
    global answer, command_to_uninstall, displayname
    check="""
WARNING: If there is only one software on the computer and you want to delete it
         Please select option 3 if there is two softwares, select 1 or 2          
\nWhat do you want to delete ?\n
\n1- PCKeeper Live
\n2- PCKeeper Antivirus
\n3- All
"""
    clear_func()

    while True:
        clear_func()
        print(check)
        answer = input("\n>>> ")
        if int(answer) == 1:
            clear_func()
            print("\nWell i will only delete PCKeeper Live")
            sleep(2)
            break
        if int(answer) == 2:
            clear_func()
            print("\nWell i will only delete PCKeeper Antivirus")
            sleep(2)
            break
        if int(answer) == 3:
            clear_func()
            print("\nHum i'm ready to delete them all !!!")
            sleep(2)
            break

    answer = int(answer)
    if answer == 1:
        displayname = ['PCKeeper', 'PCKLang.fr', 'PCKLang.en', 'PCKLang.it', 'PCKLang.es', 'PCKLang.ko']
    if answer == 2:
        displayname = ['PCKeeper Antivirus', 'PCKAVLang.fr', 'PCKAVLang.en', 'PCKAVLang.it', 'PCKAVLang.es', 'PCKAVLang.ko']
    if answer == 3:
        displayname = ['PCKeeper', 'PCKeeper Antivirus', 'PCKLang.fr', 'PCKLang.en', 'PCKLang.it', 'PCKLang.es', 'PCKAVLang.fr', 'PCKAVLang.en', 'PCKAVLang.it', 'PCKAVLang.es', 'PCKLang.ko', 'PCKAVLang.ko']
    command_to_uninstall = []


def get_users():
    """This function help to get all user account"""
    global list_users
    clear_func()
    list_users = {os.environ["USERNAME"]: 'FALSE'}
    temp = sub.check_output("wmic useraccount get Name,Disabled", shell=True).decode("utf-8").split("\r\r\n")
    temp.pop(0)
    temp.pop(-1)
    temp.pop(-1)

    for user in temp:
        try:
            temp1 = re.sub(r"\s+", ":", user)
            temp1 = temp1.split(":")
            list_users[temp1[1]] = temp1[0]
        except IndexError:
            pass

    if len(list_users) > 3:
        try:
            temp = sub.check_output("wmic ComputerSystem get Domain", shell=True).decode("utf-8")       
            if os.environ["USERDOMAIN"].lower() in temp or os.environ["USERDOMAIN"].upper() in temp:
                is_domain = True
                check = "Detected {0} users in  Domain {1}.lcl\nDo you want me to check all user folders or only those which are on this computer ?\nType 'A' for all users and 'C' for users on this computer\n".format(len(list_users), os.environ["USERDOMAIN"])
                print(check)
                choice = input(">>> ").lower()
            else:
                is_domain = False
                check = "Detected {0} users\nDo you want me to check all user folders or only those which are on this computers?\nType 'A' for all users and 'C' for users on this computer\n".format(len(list_users))
                print(check)
                choice = input(">>> ").lower()
        except KeyError:
            check = "Detected {0} users\nDo you want me to check all user folders or only those which are on this computers?\nType 'A' for all users and 'C' for users on this computer\n".format(len(list_users))
            print(check)
            choice = input(">>> ").lower()

        while choice != "a" and choice != "c":
            clear_func()
            print(check)
            choice = input(">>> ").lower()
            continue

        if choice == 'a':
            if is_domain:
                print("\nOk, i will check all {0} users \n".format(len(list_users)))
                return
            else:
                list_users = {os.environ["USERNAME"]: 'FALSE'}
                for user in os.listdir(r"{0}\Users".format(os.environ["SYSTEMDRIVE"])):
                    list_users[user] = 'FALSE'
                print("\nOk, i will check all {0} users in the computer\n".format(len(list_users)))
                return

        if choice == 'c':
            if is_domain:
                list_users = dict()
                list_users = {os.environ["USERNAME"]: 'FALSE'}
                for user in os.listdir(r"{0}\Users".format(os.environ["SYSTEMDRIVE"])):
                    list_users[user] = 'FALSE'
                print("\nOk, i will check all {0} users in the computer\n".format(len(list_users)))
                return
            else:
                list_users = {os.environ["USERNAME"]: 'FALSE'}
                for user in os.listdir(r"{0}\Users".format(os.environ["SYSTEMDRIVE"])):
                    list_users[user] = 'FALSE'
                print("\nOk, i will check all {0} users in the computer\n".format(len(list_users)))
                return
    else:
        return True
            

def launch_func():
    """This function create the registry backup"""
    global disk
    a = datetime.now()
    disk = os.environ['SYSTEMDRIVE']
    os.chdir(os.environ['SYSTEMROOT'][0:3])

    if os.path.isdir("PCK-BACKUP") == True:
        pass
    else:
        os.makedirs("PCK-BACKUP")
    os.chdir("PCK-BACKUP")
    if os.path.isfile(a.strftime(FORMAT)) == False:
        try:
            sub.call('regedit /e "PCK-{0}.reg"'.format(a.strftime(FORMAT)), stderr=sub.PIPE, shell=True)
            print("\nBACKUP REGISTRY DONE\n")
        except sub.CalledProcessError as e:
            print(("\n{0} happend while trying to create the registry backup!\n").format(str(e)))
    return True


def restore_point():
    """This function create the restore point"""
    clear_func()
    disk = os.environ['SYSTEMDRIVE']
    free_space = str(sub.check_output('wmic /node:"%COMPUTERNAME%" LogicalDisk Where DriveType="3" Get DeviceID,FreeSpace|find /I "{0}"'.format(disk), shell=True))
    free_space = re.search(r"(\d.+\s)", free_space, re.I)
    try:
        free_space = int(free_space.group())
        free_space = free_space / 2**30
        
        print("\nFree Space on Disk {0}\ is {1:.2f}GB\n20GB is the minimum amount recommended".format(disk, free_space))
        color_white()
        if free_space < 20:
            choice = input("\n*Not enough space to create a restore point, do you want me to skip the backup?\nyes to skip and no to exit: ")
            if choice.lower() == "y" or choice.lower() == "yes":
                return
            else:
                exit()
        else:
            resize_value = input("\nEnter the amount of space beetween 20 and 30GB\nOr Just Press Enter for the minimum: ")
            if resize_value == "":
                resize_value = 20
            print("\n\n")
            if platform.machine() == 'AMD64':
                c = wmi.WMI()
                process_id, return_value = c.Win32_Process.Create(CommandLine="cmd.exe /C vssadmin Resize ShadowStorage /For={0} /On={0} /Maxsize={1}GB".format(disk, resize_value))
            else:
                sub.call("vssadmin Resize ShadowStorage /For={0} /On={0} /Maxsize={1}GB".format(disk, resize_value), shell=True)
            update = wmi.WMI(moniker="winmgmts:root/default:SystemRestore")
            try:
                update.CreateRestorePoint ("PCK SOFTWARE REMOVER", 100, 1)
                print("\nSuccessfully created the resotre point\n")
                return True
            except :
                print("\nSystem restore not enabled , enabling it!\n")
                update.Enable ("{0}".format(disk[0]))
                update.CreateRestorePoint ("PCK SOFTWARE REMOVER", 100, 1)
                print("\Successfully created the resotre point\n")
                return True
    except AttributeError:
        print("\nCouldn't Get The Free Space on Disk {0}\n".format(disk))
        return True


def uninstalling_pck():
    """This function help to uninstall PCKeeper Software"""
    global displayname, command_to_uninstall    
    uninstaller = wmi.WMI()
    sub.call("cls", shell=True)
    print ("\nSearching for PCKeeper products...\n")

    for soft in displayname:
        for product in uninstaller.Win32_Product(Name = soft):
            print ("\nUninstalling  {0}...\n".format(product.Name))
            try:
                result = product.Uninstall()
            except :
                pass

    for command in command_to_uninstall:
        try:
            sub.call(command, stderr=sub.PIPE, shell=True)
        except sub.CalledProcessError :
            pass
    return "\nDONE WITH THE UNINSTALLING PCKEEPER SOFTWARE\n"


def get_software():
    global answer
    """This function help to found PCKeeper Software in the registry
       And it's also check for pckeeper MSI FILES """
    global displayname, command_to_uninstall, msi_files, msi_files2

    if answer != 1 and answer != 2:
        try:
            a =  sub.check_output('''wmic product where "Vendor like 'Essentware'" get PackageCache''', shell=True)
            a = a.decode("utf-8")
            msi_files = a.split("\r\r\n")
            msi_files.pop(0)
            msi_files.pop(-1)
            msi_files.pop(-1)
        except sub.CalledProcessError :
            pass

        try:
            a =  sub.check_output('''wmic product where "Vendor like 'Kromtech'" get PackageCache''', shell=True)
            a = a.decode("utf-8")
            msi_files2 = a.split("\r\r\n")
            msi_files2.pop(0)
            msi_files2.pop(-1)
            msi_files2.pop(-1)
        except sub.CalledProcessError :
            pass

    key_folders = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall']

    for keyVal in key_folders:
        subkey = []
        try:
            aKey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, keyVal, 0, winreg.KEY_ALL_ACCESS)
        except:
            continue
        try:
            i = 0
            while True:
                    asubkey = winreg.EnumKey(aKey, i)
                    subkey.append("{0}\{1}".format(keyVal, asubkey))
                    i += 1
        except WindowsError:
            pass

        for key in subkey:
            akey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'{0}'.format(key), 0, winreg.KEY_ALL_ACCESS)
            try:
                dispname = winreg.QueryValueEx(akey, 'DisplayName')

                if answer == 1:
                    if 'PCKeeper' in dispname[0] and 'PCKeeper Antivirus' not in dispname[0]:
                        try:
                            displayname.append(dispname[0])
                            command = winreg.QueryValueEx(akey, 'UninstallString')
                            command_to_uninstall.append(command[0])
                        except WindowsError:
                            pass

                elif answer == 2:
                    if 'PCKeeper Antivirus' in dispname[0]:
                        try:
                            displayname.append(dispname[0])
                            command = winreg.QueryValueEx(akey, 'UninstallString')
                            command_to_uninstall.append(command[0])
                        except WindowsError:
                            pass

                else:
                    if 'PCK' in dispname[0]:
                        try:
                            displayname.append(dispname[0])
                            command = winreg.QueryValueEx(akey, 'UninstallString')
                            command_to_uninstall.append(command[0])
                        except WindowsError:
                            pass
                    if 'AccountService' in dispname[0]:
                        try:
                            displayname.append(dispname[0])
                            command = winreg.QueryValueEx(akey, 'UninstallString')
                            command_to_uninstall.append(command[0])
                        except WindowsError:
                            pass
            except WindowsError:
                pass
    return True


def remove_files_and_dirs():
    """This function help to remove PCKeeper dirs and files"""
    global msi_file, msi_file2, list_users
    global answer

    disk = os.environ['SYSTEMDRIVE']
    Program_Files = os.environ["ProgramFiles"]

    if platform.machine == 'AMD64':
        Program_Files_x86 = os.environ("ProgramFiles(x86)")
    program_data = os.environ['PROGRAMDATA']
    local_temporary_dir = r'{0}\Users\{1}\AppData\Local\Temp'
    local_appdata = r"{0}\Users\{1}\AppData\Local"
    app_data = os.environ['APPDATA']
    public_folder = os.environ['PUBLIC']
    file_in_programfile = [r'Essentware\Common\AccountService.exe', r'Essentware\PCKAV\PCKAVService.exe', r'Essentware\PCKeeper\OneClickFixService.exe', r'Essentware\PCKeeper\fileHiders.exe', r'Essentware\PCKeeper\fileHiders.sys', r'Essentware\PCKAV\zeoscanner.exe', r'Essentware\PCKAV\zeoscanner.sys']
    programdata_dir = ['Essentware', 'Kromtech', 'Microsoft\Windows\Start Menu\Programs\Essentware', 'Microsoft\Windows\Start Menu\Programs\Kromtech','Application Data\Essentware', 'Application Data\Kromtech']
    programfil_dir = ['Essentware', 'Kromtech']
    app_data_dir = ['Essentware', 'Kromtech']
    file_in_drivers = [r'{0}\Windows\system32\drivers\fileHiders.sys', r'{0}\Windows\system32\drivers\zeoscanner.sys', r'{0}\Windows\PCKeeperCore.pdb', r'{0}\Windows\SysNative\drivers\fileHiders.sys', r'{0}\Windows\SysNative\drivers\zeoscanner.sys']
    app_localdata = ['Essentware', 'Kromtech']
    app_local_temp = [r'PCK640.msi', r'PCKAV320.msi', r'AccountSvc320.msi', r'AccountSvc640.msi', r'PCKLang.fr.x640.msi', r'installer0.exe', r'PCKLang.it.x640.msi', r'PCKLang.en.x640.msi']
    usage_log = [r"{0}\Users\{username}\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\PCKeeper.exe", r"{0}\Users\{username}\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\CrashReportSender.exe"]
    windows_prefetch = ['{0}\Windows\Prefetch\PCKAVSERVICE', '{0}\Windows\Prefetch\INSTALLER0', '{0}\Windows\Prefetch\ACCOUNTSERVICE', '{0}\Windows\Prefetch\CRASHREPORTSENDER', '{0}\Windows\Prefetch\ONECLICKFIXSERVICE', '{0}\Windows\Prefetch\PCKAV', '{0}\Windows\Prefetch\PCKEEPER INSTALLER', '{0}\Windows\Prefetch\PCKEEPER ANTIVIRUS INSTALLER', '{0}\Windows\Prefetch\PCKEEPER']
    pck_icons = [r'{0}\Desktop\PCKeeper.lnk', r'{0}\Desktop\PCKeeper Antivirus.lnk']
    pck_icons2 = [r'IconPCKeeper.exe', r'IconPCKAV.exe']
    pckeeper_files = [r'{0}\Windows\system32\drivers\fileHiders.sys', r'{0}\Windows\PCKeeperCore.pdb', r'{0}\Windows\SysNative\drivers\fileHiders.sys', r'{0}\Users\Public\Desktop\PCKeeper.lnk', r'{0}\ProgramData\Essentware\Installer\PCKeeper Installer.exe0.llog']
    pck_programfile_folder = [r'Essentware\PCKeeper', r'Essentware\PCKAV', r'Kromtech\PCKeeper', r'Kromtech\PCKAV']
    pckeeper_programdata_folder = ['Essentware\PCKeeper', 'Essentware\PCKeeper', r'Microsoft\Windows\Start Menu\Programs\Essentware\PCKeeper']
    pckav_files = [r'{0}\Windows\SysNative\drivers\zeoscanner.sys', r'{0}\Users\Public\Desktop\PCKeeper Antivirus.lnk', r'{0}\ProgramData\Essentware\Installer\PCKeeper Antivirus Installer.exe0.llog']
    pckav_programdata_folder = ['Essentware\PCKAV', 'Essentware\PCKAV', r'Microsoft\Windows\Start Menu\Programs\Essentware\PCKeeper Antivirus']
    
    #THIS LINE CREATE 14 THREAD THAT WILL ACTIVELLY KILL PCKEEPER SOFTWARE OR SERVICE IF THEY TRY TO BE CREATE OR START
    for killer in range(14):
        t = Thread(target=kill_service_and_process())
        t.start()

    def delete_dirs(folder):
        """FUNCTION TO DELETE PCKEEPER DIRS """
        try:
            try:
                #THIS LINE GIVE THE CURRENT USER OWNERSHIP OF PCKEEPER FOLDER
                sub.call('icacls "{0}" /setowner {1} /T /C'.format(folder, os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
            except sub.CalledProcessError :
                pass
            try:
                #THIS LINE GRANT ALL PERMISSION ON PCKEEPER FOLDER FOR THE CURRENT USER
                sub.call('icacls "{0}" /grant {1}:(OI)(CI)F /T /C'.format(folder, os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
            except sub.CalledProcessError :
                pass
            try:
                #THIS LINE DELETE PCKEEPER FOLDER RECURSIVELLY
                sub.call('RD /S /Q "{0}"'.format(folder), stdout=FNULL, stderr=sub.STDOUT, shell=True)
            except sub.CalledProcessError :
                pass
        except sub.CalledProcessError :
            pass          
        except FileNotFoundError :
            pass

    def delete_files(file):
        try:
            try:
                sub.call('icacls "{0}" /setowner {1} /C'.format(file, os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
            except sub.CalledProcessError :
                pass
            try:
                sub.call('icacls "{0}" /grant {1}:(OI)(CI)F /C'.format(file, os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
            except sub.CalledProcessError :
                pass
            try:
                sub.call('del /f /s /q "{0}"'.format(file), stdout=FNULL, stderr=sub.STDOUT, shell=True)
            except sub.CalledProcessError :
                pass
        except sub.CalledProcessError :
            pass
        except OSError as e:
            pass

    if answer == 1 or answer == 2:
        os.chdir(Program_Files)
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for folder in pck_programfile_folder:
            if answer == 1 and 'PCKeeper' in folder:
               try:
                   delete_dirs(folder)
                   if os.path.isdir('{0}'.format(folder)) == False:                
                       continue
                   else:
                       shutil.rmtree('{0}'.format(folder))

               except sub.CalledProcessError :
                   pass
               except FileNotFoundError :
                   pass

            elif answer == 2 and 'PCKAV' in folder:
                try:
                    delete_dirs(folder)
                    if os.path.isdir('{0}'.format(folder)) == False:                
                       continue
                    else:
                        shutil.rmtree('{0}'.format(folder))
                except sub.CalledProcessError :
                    pass          
                except FileNotFoundError :
                    pass
    
    if answer == 1:
        os.chdir(program_data)
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for folder in pckeeper_programdata_folder:
            try:
                delete_dirs(folder)
                if os.path.isdir('{0}'.format(folder)) == False:                
                    continue
                else:
                    shutil.rmtree('{0}'.format(folder))
            except sub.CalledProcessError :
                pass
            except FileNotFoundError :
                pass
        for file in pckeeper_files:
            delete_files(file.format(disk))
            if os.path.isfile(file) == False:
                continue
            else:
                os.remove(file)

    if answer == 2:
        os.chdir(program_data)
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for folder in pckav_programdata_folder:
            try:
                delete_dirs(folder)
                if os.path.isdir('{0}'.format(folder)) == False:                
                    continue
                else:
                    shutil.rmtree('{0}'.format(folder))
            except sub.CalledProcessError :
                pass
            except FileNotFoundError :
                pass
        for file in pckeeper_files:
            try:
                delete_files(file.format(disk))
                if os.path.isfile(file) == False:
                    continue
                else:
                    os.remove(file)
            except sub.CalledProcessError :
                pass
            except FileNotFoundError :
                pass

    if answer != 1 and answer != 2:
        os.chdir(app_data)
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for folder in app_data_dir:
            try:
                delete_dirs(folder)
                if os.path.isdir('{0}'.format(folder)) == False:                
                    continue
                else:
                    shutil.rmtree('{0}'.format(folder))
            except sub.CalledProcessError :
                pass
            except FileNotFoundError :
                pass
        
        os.chdir(Program_Files)
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for folder in programfil_dir:
            try:
                delete_dirs(folder)
                if os.path.isdir('{0}'.format(folder)) == False:                
                    continue
                else:
                    shutil.rmtree('{0}'.format(folder))
            except sub.CalledProcessError :
                pass
            except FileNotFoundError :
                pass
            
        os.chdir(program_data)
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for folder in programdata_dir:
            try:
                delete_dirs(folder)
                if os.path.isdir('{0}'.format(folder)) == False:                
                    continue
                else:
                    shutil.rmtree('{0}'.format(folder))
            except sub.CalledProcessError : 
                pass          
            except FileNotFoundError :
                pass

        for user in list_users.keys():
            if list_users[user] == 'FALSE':
                try:
                    os.chdir(local_temporary_dir.format(disk, user))
                    print("\nCurrent directory : {0}\n".format(os.getcwd()))
                    for file in app_local_temp:
                        delete_files(file)
                        if os.path.isfile(file) == False:
                            continue
                        else:
                            os.remove(file)
                except FileNotFoundError:
                    continue

        os.chdir(os.environ["SYSTEMROOT"])
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for file in usage_log:
            try:
                try:
                    sub.call('icacls "{0}" /setowner {1} /C'.format(file.format(disk, username=os.environ["USERNAME"]), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('icacls "{0}" /grant {1}:(OI)(CI)F /C'.format(file.format(disk, username=os.environ['USERNAME']), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('del /f /s /q "{0}"'.format(file.format(disk, username=os.environ['USERNAME'])), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass

                if os.path.isfile('{0}'.format(file.format(disk, username=os.environ['USERNAME']))) == False:
                    continue
                else:
                    os.remove(file.format(disk, username=os.environ['USERNAME']))

            except sub.CalledProcessError :
                pass

            except OSError as e:
                pass

        for user in list_users.keys():
            if list_users[user] == 'FALSE':
                try:
                    os.chdir(local_appdata.format(disk, user))
                    print("\nCurrent directory : {0}\n".format(os.getcwd()))
                    for folder in app_localdata:
                        try:
                            delete_dirs(folder)
                            if os.path.isdir('{0}'.format(folder)) == False:                
                                continue
                            else:
                                shutil.rmtree('{0}'.format(folder))
                        except sub.CalledProcessError :    
                            continue
        
                        except FileNotFoundError :
                            pass
                except FileNotFoundError:
                    continue

        os.chdir(Program_Files)
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for file in file_in_programfile:
            try:
                delete_files(file)
            except sub.CalledProcessError :
                pass

            except OSError as e:    
                pass

        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for file in usage_log:
            try:
                try:
                    sub.call('icacls "{0}" /setowner {1} /C'.format(file.format(disk, username=os.environ["USERNAME"]), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('icacls "{0}" /grant {1}:(OI)(CI)F /C'.format(file.format(disk, username=os.environ['USERNAME']), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('del /f /s /q "{0}"'.format(file.format(disk, username=os.environ['USERNAME'])), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass

                if os.path.isfile('{0}'.format(file.format(disk, username=os.environ['USERNAME']))) == False:
                    continue
                else:
                    os.remove(file.format(disk, username=os.environ['USERNAME']))

            except sub.CalledProcessError :
                pass

            except OSError :
                pass

        os.chdir("{0}\Windows\Installer".format(disk))
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for file in msi_files:
            a = re.search("(\d.+\S)", file, re.I)
            try:
                try:
                    file = a.group()
                except AttributeError:
                    continue
                delete_files(file)
                if os.path.isfile(file) == False:
                    continue
                else:
                    os.remove(file)
            except AttributeError :
                pass
            except OSError :
                pass
            except NoneType:
                pass

        os.chdir("{0}\Windows\Installer".format(disk))
        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for file in msi_files2:
            a = re.search("(\d.+\S)", file, re.I)
            try:
                try:
                    file = a.group()
                except AttributeError :
                    continue
                delete_files(file)
                if os.path.isfile(file) == False:
                    continue
                else:
                    os.remove(file)
            except AttributeError :
                pass
            except OSError :
                pass

        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for file in file_in_drivers:
            try:
                try:
                    sub.call('icacls "{0}" /setowner {1} /C'.format(file.format(disk), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('icacls "{0}" /grant {1}:(OI)(CI)F /C'.format(file.format(disk), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('del /f /s /q "{0}"'.format(file.format(disk)), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
            
                if os.path.isfile(file.format(disk)) == False:
                    continue
                else:
                    os.remove(file.format(disk))

            except sub.CalledProcessError :
                pass

            except OSError :
                pass

        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for file in windows_prefetch:
            try:
                try:
                    sub.call('icacls "{0}" /setowner {1} /T /C'.format(file.format(disk), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('icacls "{0}" /grant {1}:(OI)(CI)F /C'.format(file.format(disk), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('del /f /s /q "{0}*"'.format(file.format(disk)), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
            
                if os.path.isfile(file.format(disk)) == False:
                    continue
                else:
                    os.remove(file.format(disk))

            except sub.CalledProcessError :
                pass

            except OSError :
                pass

        print("\nCurrent directory : {0}\n".format(os.getcwd()))
        for icon in pck_icons:
            try:
                try:
                    sub.call('icacls "{0}" /setowner {1} /T /C'.format(icon.format(public_folder), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('icacls "{0}" /grant {1}:(OI)(CI)F /C'.format(icon.format(public_folder), os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('del /f /s /q "{0}"'.format(icon.format(public_folder)), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass

                if os.path.isfile(icon.format(public_folder)) == False:
                    continue
                else:
                    os.remove(icon.format(public_folder))

            except sub.CalledProcessError :
                pass

            except OSError :
                pass

            except FileNotFoundError :
                pass

    print("\nCurrent directory : {0}\n".format(os.getcwd()))
    for icon in pck_icons2:
        for dirpath, dirname, files in os.walk("{0}\Windows\Installer".format(disk)):
            output = os.listdir(dirpath)
            if icon in output:
                cleanit = "{0}\{1}".format(dirpath, icon)
                try:
                    sub.call('icacls "{0}" /setowner {1} /C'.format(cleanit, os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('icacls "{0}" /grant {1}:(OI)(CI)F /C'.format(cleanit, os.environ["USERNAME"]), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
                if answer == 1 and r'IconPCKeeper.exe' in icon:
                    try:
                        sub.call('del /f /s /q "{0}"'.format(cleanit), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                    except sub.CalledProcessError :
                        pass
                if answer == 2 and r'IconPCKAV.exe' in icon:
                    try:
                        sub.call('del /f /s /q "{0}"'.format(cleanit), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                    except sub.CalledProcessError :
                        pass
                if answer == 3:
                    try:
                        sub.call('del /f /s /q "{0}"'.format(cleanit), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                    except sub.CalledProcessError :
                        pass

def kill_service_and_process():
    global answer
    Program_Files = os.environ["ProgramFiles"]
    pckeeper_process = [r'PCKeeper.exe', r'PCKeeperService.exe', r'PCKElevatedHost.exe', r'fileHiders.exe', r'OneClickFixService.exe']
    pckav_process = [r'PCKAV.exe', r'PCKAVService.exe', r'zeoscanner.exe']
    pckeeper_services = ['PCKeeperOcfService', 'PCKeeper2Service', 'fileHiders']
    pckav_services = ['PCKAVService', 'ZeoScanner'] 
    process_to_kill = [r'PCKAV.exe', r'PCKeeper.exe', r'PCKAVService.exe', r'PCKeeperService.exe', r'OneClickFixService.exe', r'AccountService.exe', r'CrashReportSender.exe', r'PCKElevatedHost.exe', r'fileHiders.exe', r'zeoscanner.exe']
    service_to_kill = ['PCKAVService', 'AccountService', 'PCKeeperOcfService', 'PCKeeper2Service', 'ZeoScanner', 'fileHiders']

    if answer == 2 or answer == 3:
        try:
            sub.call('taskkill /im PCKAV.exe /f', stderr=sub.PIPE, shell=True)
        except:
            pass
    if answer == 1 or answer == 3:
        try:
            sub.call('taskkill /im PCKeeper.exe /f', stderr=sub.PIPE, shell=True)
        except:
            pass
    if answer != 1 and answer != 2:
        for process in process_to_kill:
            try:
                sub.call("taskkill /im {0} /f".format(process), stderr=sub.PIPE, shell=True)
            except sub.CalledProcessError :
                pass
        for service in service_to_kill:
            try:
                sub.call("net stop {0}".format(service), stderr=sub.PIPE, shell=True)
            except sub.CalledProcessError :
                pass
            try:
                sub.call('sc delete "{0}"'.format(service), stdout=FNULL, stderr=sub.STDOUT, shell=True)
            except sub.CalledProcessError :
                pass

    if answer == 1 or answer == 2:
        if answer == 1:
            for process in pckeeper_process :
                try:
                    sub.call("taskkill /im {0} /f".format(process), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError :
                    pass
        elif answer == 2:
            for process in pckav_process:
                try:
                    sub.call("taskkill /im {0} /f".format(process), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError :
                    pass
        if answer == 1:
            for service in pckeeper_services :
                try:
                    sub.call("net stop {0}".format(service), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('sc delete "{0}"'.format(service), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass
        elif answer == 2:
            for service in pckav_services:
                try:
                    sub.call("net stop {0}".format(service), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError :
                    pass
                try:
                    sub.call('sc delete "{0}"'.format(service), stdout=FNULL, stderr=sub.STDOUT, shell=True)
                except sub.CalledProcessError :
                    pass


def delete_register():
    """THIS FUNCTION HELP TO DELETE REGISTRY KEYS"""
    global list_users, hkl_sid_value, answer
    disk = os.environ["SYSTEMDRIVE"]
    hkl_sid_value = []

    for user in list_users.keys():
        try:
            temp = (sub.check_output("""wmic useraccount where "Name like '{0}'" get Sid""".format(user), shell=True)).decode('utf-8').split("\r\r\n")
            temp.pop(0)
            temp.pop(-1)
            temp.pop(-1)
            if temp == []:
                continue
            temp = "".join(temp)
            temp = re.search(r"(.+\S)", temp, re.I)
            try:
                hkl_sid_value.append(temp.group())
            except TypeError:
                continue
            except AttributeError:
                continue
        except sub.CalledProcessError:
            continue

    hkl_root = [r'CLSID\{F55EA208-E122-4B4E-8483-4404A1CC9569}', r'CLSID\{990F7D4F-09EF-47DF-9ABE-BAF2DCCF5C4B}', r"Installer\Products\91D74906933C99B4986DCED8BF2A728B", r'*\shellex\ContextMenuHandlers\PCKAVShell32', r'*\ShellEx\{72DBECE7-D912-4A8F-841C-A521B7447463}', r'HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\PCKeeperShell32', r'CLSID\{00000323-0000-0000-C000-000000000046}']
    hkl_local_machine = [r'SOFTWARE\Kromtech', r'SOFTWARE\Essentware', r'Software\Kromtech', r'Software\Essentware', r'SOFTWARE\Classes\AppID\{AF85DB83-06F2-4ECF-97CF-C46EDB06BE29}', r'SOFTWARE\Classes\CLSID\{990F7D4F-09EF-47DF-9ABE-BAF2DCCF5C4B}', r'SOFTWARE\Classes\AppID\{E8EB2F1F-661E-4A7F-8F9A-77DEB757A906}', r'SOFTWARE\Classes\CLSID\{6AF595D6-D4A0-4ACA-ADD4-62034EE9FF3A}', r'SOFTWARE\Classes\AppID\{56AD7EEE-D6C0-410E-8A7B-811DEA764554}', r'SOFTWARE\Classes\CLSID\{206E5E13-3B8F-4146-9C21-F18A63A9689B}', r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PCKeeper Installer.exe', r'SOFTWARE\Classes\CLSID\{CF6E1E3B-5B36-4A71-9105-DC75B4089D8C}', r'SOFTWARE\Classes\CLSID\{0319DE47-F039-45DC-A213-DBB61C6AE509}', r'SOFTWARE\Classes\CLSID\{074BFF31-CA38-43C4-8F25-79213AD708EF}', r'SOFTWARE\Classes\CLSID\{0D838143-D511-4555-8B97-16C3CF5A780D}', r'SOFTWARE\Classes\CLSID\{16A94A89-66C4-4990-896C-5FC3E1557FFD}', r'SOFTWARE\Classes\CLSID\{2B5E8E95-F503-4530-A340-53DE89F3358F}', r'SOFTWARE\Classes\CLSID\{2F8F99FD-7C0E-4150-8DFD-13B1F4FBD916}', r'SOFTWARE\Classes\CLSID\{33B2A2E0-18F6-45CB-8080-04320066A4A1}', r'SOFTWARE\Classes\CLSID\{503F82AB-1549-4B08-AF10-289CCCF3BE4B}', r'SOFTWARE\Classes\CLSID\{6AF595D6-D4A0-4ACA-ADD4-62034EE9FF3A}', r'SOFTWARE\Classes\CLSID\{6F09F687-2C4C-4A37-8D7A-2CB76D2B3F71}', r'SOFTWARE\Classes\CLSID\{723F0E89-F10C-4D28-A46C-934513EA963A}', r'SOFTWARE\Classes\CLSID\{7944171A-50CC-479E-A6FC-B1E25E665C25}', r'SOFTWARE\Classes\CLSID\{7A2BA8C4-F382-4DD1-A6D2-A86C6D66C4F9}', r'SOFTWARE\Classes\CLSID\{80E9CB05-9C8B-4B85-8A66-D81092F5AF60}', r'SOFTWARE\Classes\CLSID\{817BF5D8-380E-44F4-8E61-43E7ECF74B53}', r'SOFTWARE\Classes\CLSID\{8888A22B-3380-4C2B-950F-A5B6EC527A4B}', r'SOFTWARE\Classes\CLSID\{9443C19D-B318-4EBD-8A7F-6A50D0472FB4}', r'SOFTWARE\Classes\CLSID\{95CAD169-7912-410E-8C8A-7BA1729BD8F7}', r'SOFTWARE\Classes\CLSID\{B462C1CA-E368-4321-B0B1-0453E4AB6FDB}', r'SOFTWARE\Classes\CLSID\{CCF68051-721D-40C7-812D-86ED0FDE7411}', r'SOFTWARE\Classes\CLSID\{D8F2F7F9-F8F3-4562-9FDA-C1E2DAE60A30}', r'SOFTWARE\Classes\CLSID\{DEE0443A-95B1-41DF-B50A-409FDEA53644}', r'SOFTWARE\Classes\CLSID\{F55EA208-E122-4B4E-8483-4404A1CC9569}', r'SOFTWARE\Classes\CLSID\{F6649783-7559-4772-96C7-02D33BEACD8C}', r'SOFTWARE\Classes\CLSID\{05562BE7-0EFC-4BD2-BD8F-FAA363E68410}', r'SOFTWARE\Classes\CLSID\{B52115B1-936F-4EEA-A363-A535FB1942B7}', r'SOFTWARE\Classes\TypeLib\{D062B23B-F8EE-40EC-BF3F-7DB0E9FE1232}', r'SOFTWARE\Classes\TypeLib\{D3F79FC5-65FE-4650-8979-3BF0CCF02C1A}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E44BBEE3-3F83-4670-9E2E-EE0556442287}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E7E7B26A-88AA-48B0-A47C-173C062FD904}', r'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\lnkfile\shellex\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\f', r'SOFTWARE\Classes\Interface\{CF6E1E3B-5B36-4A71-9105-DC75B4089D8C}', r'SOFTWARE\Classes\Interface\{0319DE47-F039-45DC-A213-DBB61C6AE509}', r'SOFTWARE\Classes\Interface\{074BFF31-CA38-43C4-8F25-79213AD708EF}', r'SOFTWARE\Classes\Interface\{0D838143-D511-4555-8B97-16C3CF5A780D}', r'SOFTWARE\Classes\Interface\{206E5E13-3B8F-4146-9C21-F18A63A9689B}', r'SOFTWARE\Classes\Interface\{2B5E8E95-F503-4530-A340-53DE89F3358F}', r'SOFTWARE\Classes\Interface\{6F09F687-2C4C-4A37-8D7A-2CB76D2B3F71}', r'SOFTWARE\Classes\Interface\{7A2BA8C4-F382-4DD1-A6D2-A86C6D66C4F9}', r'SOFTWARE\Classes\Interface\{8888A22B-3380-4C2B-950F-A5B6EC527A4B}', r'SOFTWARE\Classes\Interface\{D8F2F7F9-F8F3-4562-9FDA-C1E2DAE60A30}', r'SOFTWARE\Classes\Interface\{F6649783-7559-4772-96C7-02D33BEACD8C}', r'SYSTEM\CurrentControlSet\Services\PCKAVService', r'SYSTEM\CurrentControlSet\Services\PCKeeper2Service', r'SYSTEM\CurrentControlSet\Services\PCKeeperOcfService', r'SYSTEM\CurrentControlSet\Services\ZeoScanner', r'SYSTEM\CurrentControlSet\Services\fileHiders', r'SYSTEM\CurrentControlSet\Services\AccountService', r'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\PCKeeperShell64', 'SOFTWARE\Classes\lnkfile\shellex\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{61CF52DA-5F88-4487-A6EE-24BBC4CDA657}', r'SOFTWARE\Classes\Installer\Features\2311DC2B5C57F724B860D95A705A2A6B', r'SOFTWARE\Classes\Installer\Products\2311DC2B5C57F724B860D95A705A2A6B', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\2311DC2B5C57F724B860D95A705A2A6B', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\2311DC2B5C57F724B860D95A705A2A6B', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\6746C1CA9DF5C304D9AD88BF2F78FE41', r'\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\107367941945A954DA989330ABE49075', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\91D74906933C99B4986DCED8BF2A728B', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\107367941945A954DA989330ABE49075', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\C41354CBF8653FA42AA4FBFAD36CC2A2', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\92D40EBB025BF0941AB82BE495771AAD', r'SOFTWARE\Classes\AppID\{AF85DB83-06F2-4ECF-97CF-C46EDB06BE29}', r'SOFTWARE\Classes\AppID\{88A65C27-A2AA-4F9E-B767-A1C0FA236891}', r'SOFTWARE\Classes\AppID\{56AD7EEE-D6C0-410E-8A7B-811DEA764554}', r'SOFTWARE\Classes\AppID\PCKElevatedHost.exe', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{49763701-5491-459A-AD89-3903BA4E0957}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{60947D19-C339-4B99-89D6-EC8DFBA227B8}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{BBE04D29-B520-490F-A18B-B24E5977A1DA}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{BC45314C-568F-4AF3-A24A-BFAF3DC62C2A}', r'SOFTWARE\Classes\AppID\{0022E012-E49A-44D5-8F7B-CFE27B39CDF8}']
    hkl_current_user = [r'Software\Essentware', r'SOFTWARE\Kromtech', r'Software\Classes\CLSID\{F55EA208-E122-4B4E-8483-4404A1CC9569}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run\PCKeeperLive', r'Software\Classes\CLSID\{F324E4F9-8496-40B2-A1FF-9617C1C9AFFE}', r'Software\Classes\CLSID\{75847177-f077-4171-bd2c-a6bb2164fbd0}', r'Software\Classes\CLSID\{374DE290-123F-4565-9164-39C4925E467B}', r'Software\Classes\CLSID\{E88DCCE0-B7B3-11d1-A9F0-00AA0060FA31}', r'Software\Classes\CLSID\{A07034FD-6CAA-4954-AC3F-97A27216F98A}', r'Software\Classes\CLSID\{00000323-0000-0000-C000-000000000046}', r'Software\Classes\WOW6432Node\CLSID\{F5078F32-C551-11D3-89B9-0000F81FE221}']
    hkl_users = [r'{0}\Software\Essentware', r'{0}\Software\Kromtech']
    hklm_value_to_delete = {r'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved': [r'{05562BE7-0EFC-4BD2-BD8F-FAA363E68410}', r'{B52115B1-936F-4EEA-A363-A535FB1942B7}', r'{828FB706-5749-4255-862F-3D30FCF017E1}', r'{40B50C00-06BB-415F-8F4E-6DEF53957ABA}']}
    hkl_user_value_to_delete = {r'{0}\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run': [r'PCKeeperLive', r'PCKeeper Antivirus', r'PCKeeper Antivirus', r'PCKeeperLive'], r'{0}\Software\Microsoft\Windows\CurrentVersion\Run': [r'PCKeeperLive', r'PCKeeper Antivirus',  r'PCKeeperLive', r'PCKeeper Antivirus']}
    hkl_current_user_value_to_delete = {r'Software\Microsoft\Windows\CurrentVersion\Run': [r'PCKeeper Antivirus', r'PCKeeperLive']}
    pck_hkl_local_machine = [r'SOFTWARE\Kromtech\{0}', r'SOFTWARE\Essentware\{0}', r'Software\Kromtech\{0}', r'Software\Essentware\{0}']
    pck_hkl_current_user = [r'Software\Essentware\{0}', r'SOFTWARE\Kromtech\{0}', r'SOFTWARE\Essentware\{0}', r'Software\Kromtech\{0}']
    pck_hkl_users = [r'{0}\SOFTWARE\Essentware\{1}', r'{0}\SOFTWARE\Kromtech\{1}']
    pcklive_hkl_local_machine =[r'SOFTWARE\Classes\AppID\{56AD7EEE-D6C0-410E-8A7B-811DEA764554}', r'SOFTWARE\Classes\AppID\{E8EB2F1F-661E-4A7F-8F9A-77DEB757A906}', r'SOFTWARE\Classes\WOW6432Node\CLSID\{05562BE7-0EFC-4BD2-BD8F-FAA363E68410}', r'SOFTWARE\Classes\TypeLib\{D062B23B-F8EE-40EC-BF3F-7DB0E9FE1232}', r'SOFTWARE\Classes\TypeLib\{D3F79FC5-65FE-4650-8979-3BF0CCF02C1A}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E44BBEE3-3F83-4670-9E2E-EE0556442287}', r'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\lnkfile\shellex\ContextMenuHandlers\PCKeeperShell32', r'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\PCKeeperShell64', r'SOFTWARE\Classes\lnkfile\shellex\ContextMenuHandlers\PCKeeperShell64']
    pcklive_hklm_value_to_delete = {r'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved':[r'{05562BE7-0EFC-4BD2-BD8F-FAA363E68410}']}
    pckav_hklm_local_machine = [r'SOFTWARE\Classes\CLSID\{B52115B1-936F-4EEA-A363-A535FB1942B7}', r'SOFTWARE\Classes\TypeLib\{D3F79FC5-65FE-4650-8979-3BF0CCF02C1A}', r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{E7E7B26A-88AA-48B0-A47C-173C062FD904}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E7E7B26A-88AA-48B0-A47C-173C062FD904}', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{5A4A7D29-7589-427B-86BC-8C313278BF89}']
    pckav_hklm_value_to_delete = {r'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved':[r'{B52115B1-936F-4EEA-A363-A535FB1942B7}', r'{40B50C00-06BB-415F-8F4E-6DEF53957ABA}']}
    pcklive_current_user = {r'Software\Microsoft\Windows\CurrentVersion\Run':[r'PCKeeperLive']}
    pckav_current_user = {r'Software\Microsoft\Windows\CurrentVersion\Run' :[r'PCKeeper Antivirus']}
    pcklive_user_value_to_delete = {r'{0}\Software\Microsoft\Windows\CurrentVersion\Run':[r'PCKeeperLive']}
    pckav_user_value_to_delete = {r'{0}Software\Microsoft\Windows\CurrentVersion\Run':[r'PCKeeper Antivirus']}
    
    def delete_value_for_64(root, xkey, xvalue):
        """THIS FUNCTION DELETE REGISTRY VALUE FOR 64BIT REGISTRY"""
        try:
            key = winreg.OpenKey(root, r"{0}".format(xkey), 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
            try:
                winreg.DeleteValue(key, xvalue)
                print("\nSuccessfully deleted {0}".format(xvalue))
            except Exception :
                return
            winreg.CloseKey(key)
        except Exception :
            return

        return

    def delete_value_for_32(root, xkey, xvalue):
        try:
            key = winreg.OpenKey(root, r"{0}".format(xkey), 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_32KEY)
            try:
                winreg.DeleteValue(key, xvalue)
                print("\nSuccessfully deleted {0}".format(xvalue))
            except Exception :
                return
            winreg.CloseKey(key)
        except Exception :
            return

        return
    
    def traverse_64(root, key, list):
        try:
            hkey = winreg.OpenKey(root, r"{0}".format(key), 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY) 
            try:
                i = 0
                while True:
                    strFullSubKey = ""
                    try:
                        strSubKey = winreg.EnumKey(hkey, i)
                        strFullSubKey = key + "\\" + strSubKey
                    except WindowsError:
                        winreg.CloseKey(hkey)
                        return
                    traverse_64(root, strFullSubKey, list)
                    list.append(strFullSubKey)
                    i+=1
            except WindowsError as e:
                print(str(e))
            winreg.CloseKey(hkey)
        except Exception as e:
            return

    def traverse_32(root, key, list):
        try:
            hkey = winreg.OpenKey(root, r"{0}".format(key), 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_32KEY)

            try:
                i = 0
                while True:
                    strFullSubKey = ""
                    try:
                        strSubKey = winreg.EnumKey(hkey, i)
                        strFullSubKey = key + "\\" + strSubKey
                    except WindowsError:
                        winreg.CloseKey(hkey)
                        return
                    traverse_32(root, strFullSubKey, list)
                    list.append(strFullSubKey)
                    i+=1
            except WindowsError :
                print(str(e))
            winreg.CloseKey(hkey)
        except Exception :
            return
    
    def reg_delete_key_64(root, key):
        global list
        list = []
        try:
            traverse_64(root, key, list)
        except Exception :
            return

        for item in list:
            try:
                winreg.DeleteKey(root, item)
                print(item)
            except Exception :
                return            
        try:
            winreg.DeleteKey(root, key)
        except Exception:
            return

    def reg_delete_key_32(root, key):
        global list
        list = []
        try:
            traverse_32(root, key, list)
        except Exception :
            return
        for item in list:
            try:
                winreg.DeleteKey(root, item)
                print(item)
            except Exception :
                return            
        try:
            winreg.DeleteKey(root, key)
        except Exception:
            return

    if answer == 1 or answer == 2:
        print("\nSTARTING TO DELETE REGISTRY KEYS AND VALUES\n")
        for cles in pck_hkl_local_machine:
            if answer == 1:
                print("\nDELETING REGISTRY KEYS FOR PCKEEPER\n")
                soft = r'PCKeeper'
                try:
                    reg_delete_key_32(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles.format(soft)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(soft), str(e)))
                try:
                    #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles.format(soft)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
            if answer == 2:
                print("\nDELETING REGISTRY KEYS FOR PCKAV\n")
                soft = r'PCKAV'
                try:
                    reg_delete_key_32(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles.format(soft)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(soft), str(e)))
                try:
                    #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles.format(soft)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

        for cles in pck_hkl_local_machine:
            if answer == 1:
                print("\nDELETING REGISTRY KEYS FOR PCKEEPER\n")
                soft = r'PCKeeper'
                try:
                    reg_delete_key_64(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles.format(soft)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(soft), str(e)))
                try:
                    #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles.format(soft)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
            if answer == 2:
                print("\nDELETING REGISTRY KEYS PCKAV\n")
                soft = r'PCKAV'
                try:
                    reg_delete_key_64(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles.format(soft)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(soft), str(e)))
                try:
                    #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles.format(soft)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

        for cles in pck_hkl_current_user:
            if answer == 1:
                print("\nDELETING REGISTRY KEYS FOR PCKEEPER\n")
                soft = r'PCKeeper'
                try:
                    reg_delete_key_32(winreg.HKEY_CURRENT_USER, r"{0}".format(cles.format(soft)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(soft), str(e)))
                try:
                    #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_CURRENT_USER\{1}" /f'.format(disk, cles.format(soft)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
            if answer == 2:
                print("\nDELETING REGISTRY KEYS FOR PCKAV\n")
                soft = r'PCKAV'
                try:
                    reg_delete_key_32(winreg.HKEY_CURRENT_USER, r"{0}".format(cles.format(soft)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(soft), str(e)))
                try:
                    #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_CURRENT_USER\{1}" /f'.format(disk, cles.format(soft)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

        for cles in pck_hkl_current_user:
            if answer == 1:
                print("\nDELETING REGISTRY KEYS FOR PCKEEPER\n")
                soft = r'PCKeeper'
                try:
                    reg_delete_key_64(winreg.HKEY_CURRENT_USER, r"{0}".format(cles.format(soft)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(soft), str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_CURRENT_USER\{1}" /f'.format(disk, cles.format(soft)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
            if answer == 2:
                print("\nDELETING REGISTRY KEYS FOR PCKAV\n")
                soft = r'PCKAV'
                try:
                    reg_delete_key_64(winreg.HKEY_CURRENT_USER, r"{0}".format(cles.format(soft)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(soft), str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_CURRENT_USER\{1}" /f'.format(disk, cles.format(soft)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

        for sid in hkl_sid_value:    
            for cles in pck_hkl_users:
                if answer == 1:
                    print("\nDELETING TO DELETE REGISTRY KEYS FOR PCKEEPER\n")
                    soft = r'PCKeeper'
                    try:
                        reg_delete_key_32(winreg.HKEY_USERS, r"{0}".format(cles.format(sid, soft)))
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(cles.format(sid, soft), str(e)))
                    try:
                        sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_USERS\{1}" /f'.format(disk, cles.format(sid, soft)), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue
                if answer == 2:
                    soft = r'PCKAV'
                    print("\nDELETING REGISTRY KEYS FOR PCKAV\n")
                    try:
                        reg_delete_key_32(winreg.HKEY_USERS, r"{0}".format(cles.format(sid, soft)))
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(cles.format(sid, soft), str(e)))
                    try:
                        sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_USERS\{1}" /f'.format(disk, cles.format(sid, soft)), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue

        for sid in hkl_sid_value:    
            for cles in pck_hkl_users:
                if answer == 1:
                    print("\nDELETING REGISTRY KEYS FOR PCKEEPER\n")
                    soft = r'PCKeeper'
                    try:
                        reg_delete_key_64(winreg.HKEY_USERS, r"{0}".format(cles.format(sid, soft)))
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(cles.format(sid, soft), str(e)))
                    try:
                        sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_USERS\{1}" /f'.format(disk, cles.format(sid, soft)), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue
                if answer == 2:
                    print("\nDELETING REGISTRY KEYS FOR PCKAV\n")
                    soft = r'PCKAV'
                    try:
                        reg_delete_key_64(winreg.HKEY_USERS, r"{0}".format(cles.format(sid, soft)))
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(cles.format(sid, soft), str(e)))
                    try:
                        sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_USERS\{1}" /f'.format(disk, cles.format(sid, soft)), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue

        if answer == 1:
            print("\nDELETING REGISTRY KEYS FOR PCKEEPER\n")
            for cles in pcklive_hkl_local_machine:
                try:
                    reg_delete_key_32(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles,  str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                try:
                    reg_delete_key_64(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles, str(e)))
                try:
                    #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
        
        if answer == 2:
            print("\nDELETING REGISTRY KEYS FOR PCKAV\n")
            for cles in pckav_hklm_local_machine:
                try:
                    reg_delete_key_32(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles,  str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                try:
                    reg_delete_key_64(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles, str(e)))
                try:
                    #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass

    if answer == 1:
        print("\nDELETING REGISTRY VALUES FOR PCKEEPER\n")
        for xkey, xvalue in pcklive_hklm_value_to_delete.items():
            for value in xvalue:
                try:
                    delete_value_for_32(winreg.HKEY_LOCAL_MACHINE, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
        for xkey, xvalue in pcklive_hklm_value_to_delete.items():
            for value in xvalue:
                try:
                    delete_value_for_64(winreg.HKEY_LOCAL_MACHINE, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

    if answer == 2:
        print("\nDELETING REGISTRY VALUES FOR PCKAV\n")
        for xkey, xvalue in pckav_hklm_value_to_delete.items():
            for value in xvalue:
                try:
                    delete_value_for_32(winreg.HKEY_LOCAL_MACHINE, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
        for xkey, xvalue in pckav_hklm_value_to_delete.items():
            for value in xvalue:
                try:
                    delete_value_for_64(winreg.HKEY_LOCAL_MACHINE, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

    if answer == 1:
        print("\nDELETING REGISTRY VALUES FOR PCKEEPER\n")
        for xkey, xvalue in pcklive_current_user.items():
            for value in xvalue:
                try:
                    delete_value_for_32(winreg.HKEY_CURRENT_USER, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_CURRENT_USER\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
        for xkey, xvalue in pcklive_current_user.items():
            for value in xvalue:
                try:
                    delete_value_for_64(winreg.HKEY_CURRENT_USER, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_CURRENT_USER\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

    if answer == 2:
        print("\nDELETING REGISTRY VALUES FOR PCKAV\n")
        for xkey, xvalue in pckav_current_user.items():
            for value in xvalue:
                try:
                    delete_value_for_32(winreg.HKEY_CURRENT_USER, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_CURRENT_USER\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
        for xkey, xvalue in pckav_current_user.items():
            for value in xvalue:
                try:
                    delete_value_for_64(winreg.HKEY_CURRENT_USER, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_CURRENT_USER\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

    if answer == 1:
        print("\nDELETING REGISTRY VALUES FOR PCKEEPER\n")
        for sid in hkl_sid_value:
            for xkey, xvalue in pcklive_user_value_to_delete.items():
                for value in xvalue:
                    try:
                        delete_value_for_64(winreg.HKEY_USERS, xkey.format(sid), value)
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(xkey.format(sid), str(e)))
                    try:
                        sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_USERS\{1}" /v {2} /f'.format(disk, xkey.format(sid), value), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue

        for sid in hkl_sid_value:
            for xkey, xvalue in pcklive_user_value_to_delete.items():
                for value in xvalue:
                    try:
                        delete_value_for_32(winreg.HKEY_USERS, xkey.format(sid), value)
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(xkey.format(sid), str(e)))
                    try:
                        sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_USERS\{1}" /v {2} /f'.format(disk, xkey.format(sid), value), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue

    if answer == 2:
        print("\nDELETING REGISTRY VALUES FOR PCKAV\n")
        for sid in hkl_sid_value:
            for xkey, xvalue in pckav_user_value_to_delete.items():
                for value in xvalue:
                    try:
                        delete_value_for_64(winreg.HKEY_USERS, xkey.format(sid), value)
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(xkey.format(sid), str(e)))
                    try:
                        sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_USERS\{1}" /v {2} /f'.format(disk, xkey.format(sid), value), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue

        for sid in hkl_sid_value:
            for xkey, xvalue in pckav_user_value_to_delete.items():
                for value in xvalue:
                    try:
                        delete_value_for_32(winreg.HKEY_USERS, xkey.format(sid), value)
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(xkey.format(sid), str(e)))
                    try:
                        sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_USERS\{1}" /v {2} /f'.format(disk, xkey.format(sid), value), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue

    if answer != 1 and answer !=2:
        for cles in hkl_local_machine:
            try:
                reg_delete_key_32(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles))
            except FileNotFoundError as e:
                print("\n* {0}, following error happend {1}".format(cles, str(e)))
            try:
                #THIS LINE IS HERE TO CONFIRM IF IT'S HAS BEEN SUCCESSFULLY DELETED IF NOT IT'S WILL DELETE IT BY COMMAND LINE
                sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
            except sub.CalledProcessError:
                pass
            continue
        
        for cles in hkl_current_user:
            try:
                reg_delete_key_32(winreg.HKEY_CURRENT_USER, r"{0}".format(cles))
            except FileNotFoundError as e:
                print("\n* {0}, following error happend {1}".format(cles, str(e)))
            try:
                sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_CURRENT_USER\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
            except sub.CalledProcessError:
                pass
            continue
        
        for sid in hkl_sid_value:    
            for cles in hkl_users:
                try:
                    reg_delete_key_32(winreg.HKEY_USERS, r"{0}".format(cles.format(sid)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles.format(sid), str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_USERS\{1}" /f'.format(disk, cles.format(sid)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

        for cles in hkl_root:
            try:
                reg_delete_key_32(winreg.HKEY_CLASSES_ROOT, r"{0}".format(cles))
            except FileNotFoundError as e:
                print("\n* {0}, following error happend {1}".format(cles, str(e)))
            try:
                sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_CLASSES_ROOT\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
            except sub.CalledProcessError:
                pass
            continue

        for cles in hkl_local_machine:
            try:
                reg_delete_key_64(winreg.HKEY_LOCAL_MACHINE, r"{0}".format(cles))
            except FileNotFoundError as e:
                print("\n* {0}, following error happend {1}".format(cles, str(e)))
            try:
                sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
            except sub.CalledProcessError:
                pass
            continue
        
        for cles in hkl_current_user:
            try:
                reg_delete_key_64(winreg.HKEY_CURRENT_USER, r"{0}".format(cles))
            except FileNotFoundError as e:
                print("\n* {0}, following error happend {1}".format(cles, str(e)))
            try:
                sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_CURRENT_USER\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
            except sub.CalledProcessError:
                pass
            continue

        for sid in hkl_sid_value:    
            for cles in hkl_users:
                try:
                    reg_delete_key_64(winreg.HKEY_USERS, r"{0}".format(cles.format(sid)))
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(cles, str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_USERS\{1}" /f'.format(disk, cles.format(sid)), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

        for cles in hkl_root:
            try:
                reg_delete_key_64(winreg.HKEY_CLASSES_ROOT, r"{0}".format(cles))
            except FileNotFoundError as e:
                print("\n* {0}, following error happend {1}".format(cles, str(e)))
            try:
                sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_CLASSES_ROOT\{1}" /f'.format(disk, cles), stderr=sub.PIPE, shell=True)
            except sub.CalledProcessError:
                pass
            continue

        for xkey, xvalue in hkl_current_user_value_to_delete.items():
            for value in xvalue:
                try:
                    delete_value_for_32(winreg.HKEY_CURRENT_USER, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_CURRENT_USER\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

        for xkey, xvalue in hkl_current_user_value_to_delete.items():
            for value in xvalue:
                try:
                    delete_value_for_64(winreg.HKEY_CURRENT_USER, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_CURRENT_USER\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue
            
        for sid in hkl_sid_value:
            for xkey, xvalue in hkl_user_value_to_delete.items():
                for value in xvalue:
                    try:
                        delete_value_for_64(winreg.HKEY_USERS, xkey.format(sid), value)
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(xkey.format(sid), str(e)))
                    try:
                        sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_USERS\{1}" /v {2} /f'.format(disk, xkey.format(sid), value), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue

        for sid in hkl_sid_value:
            for xkey, xvalue in hkl_user_value_to_delete.items():
                for value in xvalue:
                    try:
                        delete_value_for_32(winreg.HKEY_USERS, xkey.format(sid), value)
                    except FileNotFoundError as e:
                        print("\n* {0}, following error happend {1}".format(xkey.format(sid), str(e)))
                    try:
                        sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_USERS\{1}" /v {2} /f'.format(disk, xkey.format(sid), value), stderr=sub.PIPE, shell=True)
                    except sub.CalledProcessError:
                        pass
                    continue
        
        for xkey, xvalue in hklm_value_to_delete.items():
            for value in xvalue:
                try:
                    delete_value_for_32(winreg.HKEY_LOCAL_MACHINE, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\System32\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue

        for xkey, xvalue in hklm_value_to_delete.items():
            for value in xvalue:
                try:
                    delete_value_for_64(winreg.HKEY_LOCAL_MACHINE, xkey, value)
                except FileNotFoundError as e:
                    print("\n* {0}, following error happend {1}".format(xkey, str(e)))
                try:
                    sub.call(r'{0}\Windows\Sysnative\reg.exe delete "HKEY_LOCAL_MACHINE\{1}" /v {2} /f'.format(disk, xkey, value), stderr=sub.PIPE, shell=True)
                except sub.CalledProcessError:
                    pass
                continue


def delete_scheduled_task():
    global answer
    """THIS FUNCTION DELETE SCHEDULED TASKS"""
    disk = os.environ['SYSTEMDRIVE']
    tasks = [r'PCKeeper updater', r'Programme de mise a jour PCKeeper']
    file_tasks = ['{0}\Windows\System32\Tasks\PCKeeper updater', '{0}\Windows\System32\Tasks\Programme de mise a jour PCKeeper', '{0}\Windows\Tasks\PCKeeper updater', '{0}\Windows\Tasks\Programme de mise a jour PCKeeper']

    for task in file_tasks:
        if answer == 1 or answer == 2:
            continue
        if answer == 3:
            try:
                sub.call('del /f /s /q "{0}"'.format(task.format(disk)), stderr=sub.PIPE, shell=True)
                if os.path.isfile(task.format(disk)) == False:
                    print("\nSuccesfully deleted {0}".format(task.format(disk)))
                else:
                    os.remove(task.format(disk))
            except OSError :
                pass
            except sub.CalledProcessError :
                pass

    for task in tasks:
        if answer == 1 or answer == 2:
            continue
        if answer == 3 or (answer != 1 and answer!= 2):
            try:
                sub.call('schtasks /delete /F /TN "{0}"'.format(task), stderr=sub.PIPE, shell=True)            
                print("\nSuccessfully deleted {0} scheduled task".format(task))
            except sub.CalledProcessError :
                pass


def restart_explorer():
    """THIS FUNCTION RESTART EXPLORER"""
    c = wmi.WMI()
    process_id, return_value = c.Win32_Process.Create(CommandLine="explorer.exe")


if __name__ == "__main__":
    while True:
        color_white()
        clear_func()
        password = getpass.getpass("Please enter the password\nThe password won't be printed to the screen\n\n\npassword> ")
        if password != "happyfixer":
            print("Wrong Password!")
            sleep(3)
            continue
        if password == "happyfixer":
            break
    main()
