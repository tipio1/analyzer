# coding: utf-8
"""_summary_
V1, July 23, tipio, SOC Analyst Intern and Shyan / based on the example of Sooty
main
"""


from analyzer import *
from summary import *


if __name__ == '__main__':
    """_summary_
    """
    try:
        print(Color.BLUE + "[+] Check API config file" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Api.apiConfig()
        
        print(Color.BLUE + "[+] Create a directory to store reports" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Directory.getReportDierectory()
        print("[+] Directory create, report link is stored in: " + str(os.getcwd()) + '/analyzer_reports')
        print("[+] IP associated with the INPUT: " + DOMAIN_NAME_TO_IP)
        
        print(Color.BLUE + "[+] Check Whois.io" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.whois()
        
        print(Color.BLUE + "[+] Check Virus Total" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.virusTotal()
        
        print(Color.BLUE + "[+] Check Duggy Tuxy's list" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.scrapDuggyTuxyRepo()

        print(Color.BLUE + "[+] Check IPsum's blacklists" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.ipsum()
        
        print(Color.BLUE + "[+] Check CriminalIP.io" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.criminalIP()
        
        print(Color.BLUE + "[+] Check AbuseIPDB" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.abuseIPDB()
        
        print(Color.BLUE + "[+] Check Alien Vault" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.otx()
        
        print(Color.BLUE + "[+] GCI report" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Country.gci()
        
        print(Color.GREEN + "[+] Report stored, here is the summary: " + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Summary.summary()
        print("--------------------------------------------------------------------------------------------------------")
    
    except Exception as err:
        print(err)
    except KeyboardInterrupt:
        print(Color.ORANGE + '[!] bye' + Color.END)
