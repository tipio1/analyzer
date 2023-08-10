# coding: utf-8
"""_summary_
V1, July 23, tipio, SOC Analyst Intern and Shyan / based on the example of Sooty
work utilities
"""

import time
import socket
import os
import json


# Classes:
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    BLUE = "\033[94m"
    END = '\033[0m'


# Constants:
try:
    KEY_FILE = "/home/keys_file.json"
    CONFIG_FILE = open(KEY_FILE, "r")
    TODAY = time.strftime("%m-%d-%Y")
    # Enter an IP or domain
    INPUT = input("Enter IP Address or Domain name: ").split()
    IP = str(INPUT[0])
    # Returns the IP address of the host (domain)
    DOMAIN_NAME_TO_IP = socket.gethostbyname(IP)
except Exception:
    print(Color.RED + "[!] Domain not found" + Color.END)


class Api:
    @staticmethod
    def apiConfig():
        """_summary_
        Check API keys config file
        """
        try:
            with CONFIG_FILE as file:
                configFile = json.load(file)
                if "api" in configFile:
                    keyNames = configFile['api']
                    print("[+] Config file found and there is APIs available for: ")
                    for key,value in keyNames.items():
                        if value not in key:
                            print("\t- " + key)
                CONFIG_FILE.close()
        except FileNotFoundError:
            print(Color.RED + '[!] keys_file.json not found, create it!' + Color.END)


class Directory:
    @staticmethod
    def getReportDierectory():
        """
        Create a folder in the current directory to store results 
        """
        try:
            if not os.path.exists('analyzer_reports/' + TODAY):
                os.makedirs('analyzer_reports/' + TODAY)
        except Exception:
            print(Color.GREEN + "[+] Existing directory" + Color.END)
