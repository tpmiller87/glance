# glance
Automates the scanning process for assess missions.

Usage:
After downloading the script, install dependencies via the included requirements.txt file:

pip3 install -r requirements.txt

Copy the python script to the directory you want the output to be put in. If testing, a "test" directory is recommended.

Input the IPs or websites into a txt file, one per line. It is fed into NMAP so it can be a single IP or CIDR.

Run the program:

python3 glance.py

You will be prompted for the txt file containing the IPs and then a name for the name of the output files.




