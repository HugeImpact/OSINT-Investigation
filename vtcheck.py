import sys, optparse, time
import requests
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi

###############################################################################
# Global Variables
###############################################################################
API_KEY="77b957701c81958971cc1fa86cbb5083639426c834dcf615118139fd4e789f81"


###############################################################################
# Check is the input is HEXADECIMAL
###############################################################################
def is_hex(usr_input):

    hex_digits = set("0123456789abcdefABCDEF")
    for char in usr_input:
        if not (char in hex_digits):
            return False
    return True

###############################################################################
# Check is the input is IPADDRESS
###############################################################################
def is_ipaddress(usr_input):

    hex_digits = set("0123456789.")
    for char in usr_input:
        if not (char in hex_digits):
            return False
    return True

###############################################################################
# Submit HASH to Virustotal
###############################################################################

def submit_file_to_vt(usr_input):

    params = {'apikey': API_KEY}
    files = {'file': (usr_input, open(usr_input, 'rb'))}

    print "[*] Submitting \"" + usr_input + "\" file to VirusTotal..."
    time.sleep(0.5)
    print '[+] Report Submitted!'

    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()
    resource = json_response['resource']

    time.sleep(0.5)
    print '[*] Waiting for Report to Complete...'
    time.sleep(35)
    print '[+] Report Ready!'
    time.sleep(0.5)
    print '[*] Creating JIRA Comment...'
    time.sleep(0.5)
    print '[+] Done!'

    params = {'apikey': API_KEY, 'resource': resource}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip, Mozilla/5.0"
    }
    
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', 
        params=params, headers=headers)
    json_scan_report = response.json()

    scan_date = json_scan_report['scan_date']
    scan_id = json_scan_report['scan_id']
    sha1 = json_scan_report['sha1']
    sha256 = json_scan_report['sha256']
    positives = json_scan_report['positives']
    total = json_scan_report['total']
    permalink = json_scan_report['permalink']

    print ''
    print '{quote}'
    print '*Results:* \t' + str(positives) + ' | ' + str(total)
    print '*Scan Date:* \t' + scan_date
    print '*SHA1:* \t' + sha1
    print '*SHA256:* \t' + sha256
    print '*Scan ID:* \t' + scan_id
    print '*Permalink:* \n' + '{code}' + permalink + '{code}'
    print '{quote}'
    print ''

###############################################################################
# Submit HASH to Virustotal
###############################################################################

def submit_hash_to_vt(usr_input):

    print "[*] Submiting "+ usr_input + " to Virustotal..."

    vt = VirusTotalPublicApi(API_KEY)
    response = vt.get_file_report(usr_input)
    print "[*] Waiting for Report..."

    json_scan_report1 = json.dumps(response, sort_keys=False, indent=4)
    json_scan_report2 = json.loads(json_scan_report1)
    
    scan_date = json_scan_report2['results']['scan_date']
    scan_id = json_scan_report2['results']['scan_id']
    sha1 = json_scan_report2['results']['sha1']
    sha256 = json_scan_report2['results']['sha256']
    positives = json_scan_report2['results']['positives']
    total = json_scan_report2['results']['total']
    permalink = json_scan_report2['results']['permalink']

    print ''
    print '{quote}'
    print '*Results:* \t' + str(positives) + ' | ' + str(total)
    print '*Scan Date:* \t' + str(scan_date)
    print '*SHA1:* \t' + sha1
    print '*SHA256:* \t' + sha256
    print '*Scan ID:* \t' + scan_id
    print '*Permalink:* \n' + '{code}' + permalink + '{code}'
    print '{quote}'
    print ""

###############################################################################
# Hash user input
###############################################################################
def hash_input(usr_input):
    user_input_sha1 = hashlib.sha1(usr_input).hexdigest()
    return user_input_sha1


###############################################################################
# Main Function
###############################################################################
def main():

    #creating command line swithes, help, etc.
    parser = optparse.OptionParser(sys.argv[0] + ' ' + '-i [HASH | URL | File Directory] -h HELP')
    parser.add_option('-i', dest='user_input', type='string', help='User needs to specify a HASH | URL | File Directory that will be uploaded to VirusTotal.')
    
    
    (options, args) = parser.parse_args()
    
    user_input = options.user_input 

#----------------------------------------------------------------------------------------
    if (user_input == None):  #Check if mandatory switch('es') are provided
        print parser.usage
        sys.exit(0) #exit

#----------------------------------------------------------------------------------------
# User's input is HASH (MD5|SHA1|SHA256)
#----------------------------------------------------------------------------------------

    if user_input:

        if is_hex(user_input) and (len(user_input) == 32 or len(user_input) == 40 or len(user_input) == 64):
            
            temp_hash = user_input

            if len(temp_hash) == 32:
                time.sleep(0.5)
                submit_hash_to_vt(temp_hash)

            elif len(temp_hash) == 40:
                time.sleep(0.5)
                submit_hash_to_vt(temp_hash)

            elif len(temp_hash) == 64:
                time.sleep(0.5)
                submit_hash_to_vt(temp_hash)

#----------------------------------------------------------------------------------------
        elif is_ipaddress(user_input):

            temp_hash = hash_input(user_input)
            print "[+] IP Address Submitted"
            print temp_hash
            #submit_hash_to_vt(temp_hash) - parsing json is an issue with IP need a new method to sumit IPs to VT

#----------------------------------------------------------------------------------------        
        elif "http://" in user_input or "https://" in user_input or "www." in user_input:

            print "Input is a url " + user_input
            
#----------------------------------------------------------------------------------------
        else:

            submit_file_to_vt(user_input)

if __name__ == "__main__":
    main()