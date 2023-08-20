# coding: utf-8
"""_summary_
V1, July 23, tipio, SOC Analyst Intern and Shyan / based on the example of Sooty
work utilities
"""

import time
import socket
import os
import json
import PyPDF2
from os.path import exists


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


class Cleaning:
    @staticmethod
    def gciClean():
        try:
            """_summary_
                Recovery and cleaning of "GCI" classification 2023
            """
            gci = exists('/home/tipio/Documents/analyzer_reports/gci.pdf')
            if gci == True:
                pass
            else:
                url = ('https://www.itu.int/dms_pub/itu-d/opb/str/D-STR-GCI.01-2021-PDF-E.pdf')
                os.system(f'wget {url} -O $HOME/Documents/analyzer_reports/gci.pdf')
            
            gci = str('analyzer_reports/gci.pdf')
            gciFileObj = open(gci, 'rb')
            gciFileReader = PyPDF2.PdfFileReader(gciFileObj)
            gciObj = gciFileReader.getPage(38)
            cgiObj1 = gciFileReader.getPage(39)
            cgiObj2 = gciFileReader.getPage(40)

            with open('analyzer_reports/gci.txt', 'w') as pdfTotxt:
                pdfTotxt.write(str(gciObj.extract_text()))
                pdfTotxt.write('\n')
                pdfTotxt.write(str(cgiObj1.extract_text()))
                pdfTotxt.write('\n')
                pdfTotxt.write(str(cgiObj2.extract_text()))
                pdfTotxt.close()
            
            with open('analyzer_reports/gci.txt', 'r') as text:
                pages = text.read()
                charToRemove = ['25Global Cybersecurity Index 2020', '3. GCI results: Score and rankings', '3.1 Global scores and ranking of countries', 'The following table sets out the score and rank for each country that took part in the questionnaire.', 'Table 3: GCI results: Global score and rank', 'Country Name Score Rank', 'Country Name Score Rank', '26Global Cybersecurity Index 2020', '27Global Cybersecurity Index 2020', '* no data collected', '** no response to the questionnaire', '(continued)']
                for char in charToRemove:
                    pages = pages.replace(char, '')

                us = ['United States of', 'America**100 1']
                for char in us:
                    pages = pages.replace(char, 'United States of America** 100 1')
            
                iran = ['Iran (Islamic Republic','of)81.07 54']
                for char in iran:
                    pages = pages.replace(char, 'Iran (Islamic Republic of) 81.07 54')

                bolivia = ['Bolivia (Plurinational','State of)16.14 140']
                for char in bolivia:
                    pages = pages.replace(char, 'Bolivia (Plurinational State of) 16.14 140')

                grenadines = ['Grenadines**12.18 154']
                for char in grenadines:
                    pages = pages.replace(char, 'Grenadines** 12.18 154')

                korea = ["Dem. People's Rep. of", 'Korea**1.35 181']
                for char in korea:
                    pages = pages.replace(char, "Dem. People's Rep. of Korea** 1.35 181")

            with open('analyzer_reports/gci.txt', 'w') as text:
                text.write(pages)
                text.close()
            
            os.system("sed '/^$/d' analyzer_reports/gci.txt > analyzer_reports/gci1.txt && sed -e 's/[\r]*$/;/' < analyzer_reports/gci1.txt | sed -e 's/ ;//g' -e 's/;//g' > analyzer_reports/gci2.txt")
            os.system("cat -A analyzer_reports/gci2.txt | awk '! a[$0]++' analyzer_reports/gci2.txt > analyzer_reports/gci3.txt")
            os.system("rm -rf analyzer_reports/gci.txt analyzer_reports/gci1.txt analyzer_reports/gci2.txt && mv analyzer_reports/gci3.txt analyzer_reports/gci.txt")
            # os.system("cat -A gci.txt")
        except Exception as err:
            print(err)