#!/usr/bin env python3

import argparse
import ctypes
import os
import re
import requests
import shutil
import sys
import urllib3

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from time import sleep
from threading import Thread

#hopefully mutes insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#FireFox selenium options
options = FirefoxOptions()
options.add_argument("--headless")
driver = webdriver.Firefox(options=options)

#implements options
parser = argparse.ArgumentParser()
parser.add_argument("-m", type=str, help="Current mission name")
parser.add_argument("-f", type=str, help="Text file with IPs to be scanned")
parser.add_argument("-i", type=str, help="IP(s) or netblocks to scan. If multiple, surround by quotes and separate with spaces.")

# Parse the options
args = parser.parse_args()

##########Actual start of the program##########
def nmap_disc_scan():
    if args.f:
        os.mkdir("nmap_output")
        # The actual NMAP discover scan, from runbook
        os.system(
        'nmap -Pn -n -sS -p 21-23,25,53,80,111,137,139,445,443,944,1433,1521,1830,3306,3389,5432,6379,8443,8080,27017-27019,28017 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 6000 -oA "nmap_output/' + args.m + '-disc" -vvv --open -iL ' + args.f + "\n")
    elif args.i:
        os.mkdir("nmap_output")
        # The actual NMAP discover scan, from runbook
        os.system(
        'nmap -Pn -n -sS -p 21-23,25,53,80,111,137,139,445,443,944,1433,1521,1830,3306,3389,5432,6379,8443,8080,27017-27019,28017 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 6000 -oA "nmap_output/' + args.m + '-disc" -vvv --open ' + args.i + "\n")
        sleep(3)
        
    print("\nYour output file is " + args.m + "-disc.nmap, .xml, and .gnmap\n")

    os.mkdir("parsed_results")

    # Taking the newly created greppable file and extracting
    # hosts that responded, creating a master list (livehosts.txt),
    # and organizing them by open ports.
    with open('nmap_output/' + args.m + '-disc.gnmap', 'r') as disc_grep:
        lines = disc_grep.readlines()
        for line in lines:
            port_pattern = re.compile(r" \d{1,5}/")
            if re.search(r"Up$", line):
                livehosts = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print(livehosts.group(0), file=open("parsed_results/livehosts.txt", "a"))
            if re.search(r"(\d{1,5}/open)", line):
                for port in re.finditer(port_pattern, line):
                    rhp_ip = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                    print(rhp_ip.group(0), file=open("parsed_results/" + port.group(0).replace('/', '') + ".txt", "a"))
                    swez = rhp_ip.group(0) + ":" + port.group(0).replace('/', '').strip()
                    if swez.endswith(":80") or swez.endswith(":8080") or swez.endswith(":8000") or swez.endswith(":3389"):
                        print("http://" + rhp_ip.group(0) + ":" + port.group(0).replace('/', '').strip(), file=open("parsed_results/web.txt", "a"))
                    if swez.endswith(":443") or swez.endswith(":8443") or swez.endswith(":3389"):
                        print("https://" + rhp_ip.group(0) + ":" + port.group(0).replace('/', '').strip(), file=open("parsed_results/web.txt", "a"))
                    if swez.endswith(":137") or swez.endswith(":139") or swez.endswith(":445"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/smb.txt", "a"))
                    if swez.endswith("21"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/ftp.txt", "a"))
                    if swez.endswith(":22"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/ssh.txt", "a"))
                    if swez.endswith(":23"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/telnet.txt", "a"))
                    if swez.endswith(":3306"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/sql_3306.txt", "a"))
                    if swez.endswith(":3389"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/rdp.txt", "a"))
                    if int(port.group(0).replace('/', '').strip()) >= int(1025):
                        print(port.group(0).replace('/', '').strip(), file=open("parsed_results/ephemeral.txt", "a"))

def nmap_full_scan():
    # Starting intense scan
    print("\nBeginning FULL scan\n")
    # The actual NMAP full scan, from runbook
    os.system(
        'nmap -Pn -n -sS -p- --min-hostgroup 255 --min-rtt-timeout 25ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 1000 -oA "nmap_output/' + args.m + '-full" -vvv --open -iL parsed_results/livehosts.txt' + "\n")
    with open('nmap_output/' + args.m + '-full.gnmap', 'r') as full_grep:
        lines = full_grep.readlines()
        for line in lines:
            pattern = re.compile(r" \d{1,5}/")
            if re.search(r"(\d{1,5}/open)", line):
                for port in re.finditer(pattern, line):
                    rhp_ip = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                    swez = rhp_ip.group(0) + ":" + port.group(0).replace('/', '').strip()
                    print(rhp_ip.group(0), file=open("parsed_results/" + port.group(0).replace('/', '') + ".txt", "a"))
                    if int(port.group(0).replace('/', '').strip()) >= int(1025):
                        print(port.group(0).replace('/', '').strip(), file=open("parsed_results/ephemeral.txt", "a"))
                    if swez.endswith(":4444"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/METASPLOIT_CHECK_NOW.txt", "a"))
                    if swez.endswith(":5985") or swez.endswith(":5986"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/WinRM.txt", "a"))
                    if swez.endswith(":1433"):
                        print(rhp_ip.group(0).strip(), file=open("parsed_results/MSSQL.txt", "a"))

def get_screenshots():
    os.mkdir("screenshots")
    with open("parsed_results/web.txt", "r") as web:
        for i in web.readlines():
            istrip = i.strip()
            fname = re.search(r"(?<=//)(.*?)(?=:)", istrip).group(0)
            try:
                if istrip.endswith(":80"):
                    driver.get(istrip) #navigates to URL
                    sleep(2) #sleeps for two seconds to load page
                    driver.save_screenshot(fname + "_80.png") #takes the screenshot, saving as IP + port
                    files = os.listdir(".")
                    for file in files:
                        if file.endswith("png"):
                            shutil.copy(file, "screenshots")
                            os.makedirs("html_build/" + fname + "_80", exist_ok=True)
                            shutil.move(file, "html_build/" + fname + "_80")
                if istrip.endswith(":8080"):
                    driver.get(istrip)
                    sleep(2)
                    driver.save_screenshot(fname + "_8080.png")
                    files = os.listdir(".")
                    for file in files:
                        if file.endswith("png"):
                            shutil.copy(file, "screenshots")
                            os.makedirs("html_build/" + fname + "_8080", exist_ok=True)
                            shutil.move(file, "html_build/" + fname + "_8080")
                if istrip.endswith(":443"):
                    driver.get(istrip)
                    sleep(2)
                    driver.save_screenshot(fname + "_443.png")
                    files = os.listdir(".")
                    for file in files:
                        if file.endswith("png"):
                            shutil.copy(file, "screenshots")
                            os.makedirs("html_build/" + fname + "_443", exist_ok=True)
                            shutil.move(file, "html_build/" + fname + "_443")
                if istrip.endswith(":8443"):
                    driver.get(istrip)
                    sleep(2)
                    driver.save_screenshot(fname + "_8443.png")
                    files = os.listdir(".")
                    for file in files:
                        if file.endswith("png"):
                            shutil.copy(file, "screenshots")
                            os.makedirs("html_build/" + fname + "_8443", exist_ok=True)
                            shutil.move(file, "html_build/" + fname + "_8443")
            except Exception:
                pass
    web.close()
    print("*******************SCREENSHOTS ARE FINISHED*************************")

def get_site_info():
    os.mkdir("web_info")
    with open("parsed_results/web.txt", "r") as web_info:
        for i in web_info.readlines():
            istrip = i.strip()
            fname = re.search(r"(?<=//)(.*?)(?=:)", istrip).group(0)
            try:
                if istrip.endswith(":80"):
                    data = requests.get(i, verify=False, timeout=10)
                    page_title = BeautifulSoup(data.text, 'html.parser')
                    for title in page_title.find_all('title'):
                        web_title = title.get_text()
                        print(web_title, file=open(fname + "_80.txt", "a"))
                    print(data.headers, file=open(fname + "_80.txt", "a"))
                    os.makedirs("html_build/" + fname + "_80", exist_ok=True)
                    shutil.copy(fname + "_80.txt", "html_build/" + fname + "_80")
                    shutil.move(fname + "_80.txt", "web_info")
                if istrip.endswith(":8080"):
                    data = requests.get(i, verify=False, timeout=10)
                    page_title = BeautifulSoup(data.text, 'html.parser')
                    for title in page_title.find_all('title'):
                        web_title = title.get_text()
                        print(web_title, file=open(fname + "_8080.txt", "a"))
                    print(data.headers, file=open(fname + "_8080.txt", "a"))
                    os.makedirs("html_build/" + fname + "_8080", exist_ok=True)
                    shutil.copy(fname + "_8080.txt", "html_build/" + fname + "_8080")
                    shutil.move(fname + "_8080.txt", "web_info")
                if istrip.endswith(":443"):
                    data = requests.get(i, verify=False, timeout=10)
                    page_title = BeautifulSoup(data.text, 'html.parser')
                    for title in page_title.find_all('title'):
                        web_title = title.get_text()
                        print(web_title, file=open(fname + "_443.txt", "a"))
                    print(data.headers, file=open(fname + "_443.txt", "a"))
                    os.makedirs("html_build/" + fname + "_443", exist_ok=True)
                    shutil.copy(fname + "_443.txt", "html_build/" + fname + "_443")
                    shutil.move(fname + "_443.txt", "web_info")
                if istrip.endswith(":8443"):
                    data = requests.get(i, verify=False, timeout=10)
                    page_title = BeautifulSoup(data.text, 'html.parser')
                    for title in page_title.find_all('title'):
                        web_title = title.get_text()
                        print(web_title, file=open(fname + "_8443.txt", "a"))
                    print(data.headers, file=open(fname + "_8443.txt", "a"))
                    os.makedirs("html_build/" + fname + "_8443", exist_ok=True)
                    shutil.copy(fname + "_8443.txt", "html_build/" + fname + "_8443")
                    shutil.move(fname + "_8443.txt", "web_info")
            except Exception:
                pass
    directory = r'html_build'
    for entry in os.scandir(directory):
        if os.path.isdir(entry.path) and not os.listdir(entry.path):
            os.rmdir(entry.path)
    directory = os.listdir(".")
    for i in directory:
        if (os.path.getsize(i)) == 0:
            os.remove(i)
    print("***************************SITE INFO IS FINISHED**********************************")

def html_pages():
    directory = os.listdir("html_build")
    os.mkdir("html_pages")
    for i in directory:
        try:
            dirs = os.listdir("html_build/" + i)
            if dirs[0].endswith(".png"):
                png = ("../" + "html_build/" + i + "/" + dirs[0])
            if dirs[1].endswith(".txt"):
                txt = ("../" + "html_build/" + i + "/" + dirs[1])
            f = open("html_pages/" + i + ".html", "w")
            html = """
            <!DOCTYPE HTML>
            <title>(_, |_ /\ |\| ( [-</title>
            <table class="center">
                <caption>(_, |_ /\ |\| ( [-</caption>
                <thead>
                <tr>
                    <th>Title & response info</th>
                    <th>Screenshot</th>
                </tr>
                </thead>
                <tbody>
                <tr>
                    <td><object data=""" + txt + """></object></td>
                    <td><img src=""" + png + """ width='90%'></td>
                </tr>
                </tbody>
            </table>
            </HTML>
                """
            f.write(html)
            f.close()

        except Exception:
            pass

def call_to_threads():
    t1_nmap_full = Thread(target=nmap_full_scan)
    t2_get_screenshots = Thread(target=get_screenshots)
    t3_site_info = Thread(target=get_site_info)
    t4_html_pages = Thread(target=html_pages)
    t1_nmap_full.start()
    t2_get_screenshots.start()
    t3_site_info.start()
    t2_get_screenshots.join()
    t3_site_info.join()
    t4_html_pages.start()


#####################################################################################
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<program starts>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#
#####################################################################################


# check if the script is being run as root on Linux or POSIX-compatible systems
if hasattr(os, "getuid") and hasattr(os, "geteuid"):
    if not (os.getuid() == 0 or os.geteuid() == 0):
        print("Must be run as root!")
        sys.exit(1)

# check if the script is being run as an administrator on Windows
elif hasattr(ctypes, "windll") and hasattr(ctypes.windll.shell32, "IsUserAnAdmin"):
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Must be run as an administrator!")
        sys.exit(1)

# if the script is not being run as root or as an administrator, exit with an error
else:
    print("Must be run as root or as an administrator!")
    sys.exit(1)

# if the script is being run as root or as an administrator, start the script.

print('\n(_, |_ /\ |\| ( [- \nfrom 〸山 \n')
sleep(2)

with open('geckodriver.log', 'w+') as fp:
    pass
if os.path.exists("screenshots"):
        shutil.rmtree("screenshots")
if os.path.exists("html_build"):
        shutil.rmtree("html_build")
if os.path.exists("html_pages"):
        shutil.rmtree("html_pages")
if os.path.exists("nmap_output"):
        shutil.rmtree("nmap_output")
if os.path.exists("parsed_results"):
        shutil.rmtree("parsed_results")
if os.path.exists("web_info"):
        shutil.rmtree("web_info")

nmap_disc_scan()
call_to_threads()
