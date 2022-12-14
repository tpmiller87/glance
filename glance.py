#!/usr/bin env python3

import argparse
import chromedriver_autoinstaller
import os
import re
import requests
import shutil
from time import sleep


from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from threading import Thread
#adding chromedriver to PATH
chromedriver_autoinstaller.install()
#chrome arguements to snapshot
chrome_options = Options()
chrome_options.add_argument("headless")
chrome_options.add_argument("--ignore-certificate-errors")
chrome_options.add_argument("--hide-scrollbars")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--window-size=1920,1080")
chrome_options.add_argument("--disable-web-security")
chrome_options.add_argument("enable-automation")
chrome_options.add_argument("--dns-prefetch-disable")
chrome_options.add_argument("--disable-gpu")
driver = webdriver.Chrome(options=chrome_options)

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--mission", type=str, help="Current mission name")
parser.add_argument("-i", "--ip_list", type=str, help="Text file with IPs to be scanned")

# Parse the command-line arguments
args = parser.parse_args()

def nmap_disc_scan():
    os.mkdir("nmap_output")
    # The actual NMAP discover scan, from runbook
    os.system(
        'nmap -Pn -n -sS -p 21-23,25,53,80,111,137,139,445,443,944,1433,1521,1830,3306,3389,5432,6379,8443,8080,27017-27019,28017 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 6000 -oA "nmap_output/' + args.mission + '-disc" -vvv --open -iL ' + args.ip_list + "\n")

    print("\nYour output file is " + args.mission + "-disc.nmap, .xml, and .gnmap\n")

    os.mkdir("parsed_results")

    # Taking the newly created greppable file and extracting
    # hosts that responded, creating a master list (livehosts.txt),
    # and organizing them by open ports.
    with open('nmap_output/' + args.mission + '-disc.gnmap', 'r') as disc_grep:
        os.chdir("parsed_results")
        lines = disc_grep.readlines()
        for line in lines:
            if re.search(r"Up$", line):
                livehosts = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print(livehosts.group(0), file=open("livehosts.txt", "a"))
            if re.search(r"(80/open)", line):
                web_80 = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print("http://" + web_80.group(0) + ":80", file=open("web.txt", "a"))
            if re.search(r"(\b443/open)", line):
                web_443 = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print("https://" + web_443.group(0) + ":443", file=open("web.txt", "a"))
            if re.search(r"(137/open|139/open|445/open)", line):
                smb_445 = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print(smb_445.group(0), file=open("smb.txt", "a"))
            if re.search(r"(21/open)", line):
                line_ftp = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print(line_ftp.group(0), file=open("ftp.txt", "a"))
            if re.search(r"(22/open)", line):
                line_ssh = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print(line_ssh.group(0), file=open("ssh.txt", "a"))
            if re.search(r"(8080/open)", line):
                line_http_8080 = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print("http://" + line_http_8080.group(0) + ":8080", file=open("web.txt", "a"))
            if re.search(r"(8443/open)", line):
                web_8443 = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print("https://" + web_8443.group(0) + ":8443", file=open("web.txt", "a"))
            if re.search(r"(3306/open)", line):
                sql_3306 = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print(sql_3306.group(0), file=open("sql_3306.txt", "a"))
            if re.search(r"(3389/open)", line):
                rdp_3389 = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                print(rdp_3389.group(0), file=open("rdp.txt", "a"))
    os.chdir("..")

def nmap_full_scan():
    # Starting intense scan
    print("\nBeginning FULL scan\n")
    # The actual NMAP full scan, from runbook
    os.system(
        'nmap -Pn -n -sS -p- --min-hostgroup 255 --min-rtt-timeout 25ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 1000 -oA "nmap_output/' + args.mission + '-full" -vvv --open -iL parsed_results/livehosts.txt' + "\n")
    with open('nmap_output/' + args.mission + '-full.gnmap', 'r') as full_grep:
        lines = full_grep.readlines()
        for line in lines:
            if re.search(r"(5985/open|5986/open)", line):
                winrm_open = re.search(r"[0-9]+(?:\.[0-9]+){3}", line)
                f = open("parsed_results/winrm.txt", "a")
                f.write(winrm_open.group(0))
                f.close()

def get_screenshots():
    os.mkdir("screenshots")
    with open("parsed_results/web.txt", "r") as web:
        scrape_these = web.readlines()
        fscrape = [x[:-1] for x in scrape_these]
        for i in fscrape:
            fname = re.search(r"(?<=//)(.*?)(?=:)", i).group(0)
            try:
                if i.endswith(":80"):
                    driver.get(i) #navigates to URL
                    sleep(2) #sleeps for two seconds to load page
                    driver.save_screenshot(fname + "_80.png") #takes the screenshot, saving as IP + port
                    files = os.listdir(".")
                    for file in files:
                        if file.endswith("png"):
                            shutil.copy(file, "screenshots")
                            os.makedirs("html_build/" + fname + "_80", exist_ok=True)
                            shutil.move(file, "html_build/" + fname + "_80")
                if i.endswith(":8080"):
                    driver.get(i)
                    sleep(2)
                    driver.save_screenshot(fname + "_8080.png")
                    files = os.listdir(".")
                    for file in files:
                        if file.endswith("png"):
                            shutil.copy(file, "screenshots")
                            os.makedirs("html_build/" + fname + "_8080", exist_ok=True)
                            shutil.move(file, "html_build/" + fname + "_8080")
                if i.endswith(":443"):
                    driver.get(i)
                    sleep(2)
                    driver.save_screenshot(fname + "_443.png")
                    files = os.listdir(".")
                    for file in files:
                        if file.endswith("png"):
                            shutil.copy(file, "screenshots")
                            os.makedirs("html_build/" + fname + "_443", exist_ok=True)
                            shutil.move(file, "html_build/" + fname + "_443")
                if i.endswith(":8443"):
                    driver.get(i)
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
        scrape_these = web_info.readlines()
        fscrape_web = [x[:-1] for x in scrape_these]
        for i in fscrape_web:
            fname = re.search(r"(?<=//)(.*?)(?=:)", i).group(0)
            try:
                if i.endswith(":80"):
                    data = requests.get(i, verify=False, timeout=10)
                    page_title = BeautifulSoup(data.text, 'html.parser')
                    for title in page_title.find_all('title'):
                        web_title = title.get_text()
                        print(web_title, file=open(fname + "_80.txt", "a"))
                    print(data.headers, file=open(fname + "_80.txt", "a"))
                    os.makedirs("html_build/" + fname + "_80", exist_ok=True)
                    shutil.copy(fname + "_80.txt", "html_build/" + fname + "_80")
                    shutil.move(fname + "_80.txt", "web_info")
                if i.endswith(":8080"):
                    data = requests.get(i, verify=False, timeout=10)
                    page_title = BeautifulSoup(data.text, 'html.parser')
                    for title in page_title.find_all('title'):
                        web_title = title.get_text()
                        print(web_title, file=open(fname + "_8080.txt", "a"))
                    print(data.headers, file=open(fname + "_8080.txt", "a"))
                    os.makedirs("html_build/" + fname + "_8080", exist_ok=True)
                    shutil.copy(fname + "_8080.txt", "html_build/" + fname + "_8080")
                    shutil.move(fname + "_8080.txt", "web_info")
                if i.endswith(":443"):
                    data = requests.get(i, verify=False, timeout=10)
                    page_title = BeautifulSoup(data.text, 'html.parser')
                    for title in page_title.find_all('title'):
                        web_title = title.get_text()
                        print(web_title, file=open(fname + "_443.txt", "a"))
                    print(data.headers, file=open(fname + "_443.txt", "a"))
                    os.makedirs("html_build/" + fname + "_443", exist_ok=True)
                    shutil.copy(fname + "_443.txt", "html_build/" + fname + "_443")
                    shutil.move(fname + "_443.txt", "web_info")
                if i.endswith(":8443"):
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


print('\n(_, |_ /\ |\| ( [- \nfrom 〸山 \n')
sleep(2)

nmap_disc_scan()
call_to_threads()
