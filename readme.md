# Readme


> ## **Discovers an IP and/or domain from the following web applications and returns a reputation score.**
> #### **V1, Started in July 23, tipio, SOC Analyst Intern and Shyan / based on the example of [Sooty](https://github.com/TheresAFewConors/Sooty/blob/master/Sooty.py)**


## In run:
- [ip2location](https://www.ip2location.io/)
- [VirusTotal](https://www.virustotal.com/gui/home/search)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Duggy Tuxy blacklist](https://github.com/duggytuxy/malicious_ip_addresses)
- [IPsum](https://github.com/stamparm/ipsum)
- [CriminalIP](https://www.criminalip.io/en)
- [OTX/AlienVault](https://otx.alienvault.com/)
- [Global Cybersecurity Index (GCI)](https://www.itu.int/epublications/publication/D-STR-GCI.01-2021-HTM-E)


## Setup
### Requirements:
- OTXv2 and PyPDF2:
```bash
cd 
pip --version  # need pip3
pip3 install OTXv2 && pip3 install PyPDF2
# If not accessible after common installation via pip3
# try:
sudo pip install OTXv2 && sudo pip install PyPDF2
# or
pip install OTXv2 && pip install PyPDF2
```

### Adjust utils.py:
- Create the key_file.json file. 
- Set the correct path for the key_file.json file in the KEY_FILE constante of `utils.py`.
    - Default: `"/home/keys_file.json"`

```json
{
    "api": {
        "ip2location": "your API key",
        "virus total": "your API key", 
        "abuseipdb": "your API key",
        "criminal ip": "your API key",
        "otx": "your API key"
    }
}     
```

### Create an alias:
- edit your `.bashrc` or `.zshrc`
```bash
alias analyzer='python3 <path of main.py directory>'
source .zshrc
```

### Run analyzer:
```bash
cd $HOME/Documents
analyzer
```

## Coming soon:
- [Threat book](https://threatbook.io/): provides high-fidelity intelligence collected from alerts from real customer cases.
- Integrate the "Red flag" report. To do this: match the domains in the list with their IP address.
    - [Red flag](https://red.flag.domains/): lists of very recently registered probably malicious domain names in french TLDs 