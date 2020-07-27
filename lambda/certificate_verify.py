''' This is used for verifying Certificates stored in Parameter Store'''
import json
import re
import os
import time
from datetime import datetime
from OpenSSL import crypto as cpt
import gnupg
import boto3

''' 
Make sure OpenSSL and gnupg dependent packages are bundled with your lambda function. these has to be built on Amazon Linux.
copy contents of site-packages parallel to this file.
copy any hidden folder contents of site-packages paralle to this file.
'''


CLIENT = boto3.client('ssm')
SNS = boto3.client('sns')
TOPIC = os.environ['SNS_TOPIC']

def expiry_date_string_to_days(expiry, today=datetime.today()):
    ''' Convert date string to days'''
    expiry_date = datetime.strptime(expiry, "%Y%m%d%H%M%SZ")
    return (expiry_date - today).days

def get_resources_from(ssm_details):
    ''' get resounces and next_token '''
    results = ssm_details['Parameters']
    resources = [result for result in results]
    next_token = ssm_details.get('NextToken', None)
    return resources, next_token

def get_cert_details(filename):
    ''' Get Certificate CN and days to expiry '''
    cert = cpt.load_certificate(cpt.FILETYPE_PEM, open(filename).read())
    #print(datetime.strptime(cert.get_notAfter(),"%Y%m%d%H%M%SZ"))
    commonname = cert.get_subject().CN
    cdays = expiry_date_string_to_days(cert.get_notAfter().decode())
    return cdays, commonname

def get_gpg_details(filename):
    ''' Get Expiry Cert details '''
    gpg_homedir = "/tmp/gpg"
    access = 0o700
    try:
        os.makedirs(gpg_homedir, access)
    except FileExistsError:
        None
    gpg = gnupg.GPG(gnupghome=gpg_homedir)
    keys = gpg.scan_keys(filename)
    for key in keys:
        expiry = key['expires']
        if not expiry:
            gpgdays = 10000
        else:
            ctime = int(expiry) - int(time.time())
            gpgdays = ctime // 86400
    return gpgdays

def get_crl_next_update(filename):
    ''' Read the CRL file and return the next update as datetime '''
    crldt = None
    crl_obj = cpt.load_crl(cpt.FILETYPE_PEM, open(filename).read())
    crl_text = cpt.dump_crl(cpt.FILETYPE_TEXT, crl_obj).decode("utf-8")
    for line in crl_text.split("\n"):
        if "Next Update: " in line:
            key, value = line.split(":", 1)
            date = value.strip()
            crldt = datetime.strptime(date, "%b %d %X %Y %Z")
            break
    return crldt


def handler(event, context):
    ''' Lambda handler '''
    regex1 = '^/.*/c[rl]*$'
    resources = []
    next_token = ' '
    while next_token is not None:
        ssm_details = CLIENT.describe_parameters(MaxResults=50, NextToken=next_token)
        current_batch, next_token = get_resources_from(ssm_details)
        resources += current_batch
    for results in resources:
        result = all(re.match(regex, results['Name']) for regex in [regex1])
        if result:
            print(results['Name'])
            response = CLIENT.get_parameter(Name=results['Name'], WithDecryption=True)
            certvalue = response['Parameter']['Value']
            fopen = open("/tmp/crt.txt", 'w')
            fopen.writelines(certvalue)
            fopen.close()
            if 'gpg' in results['Name']:
                daystoexpire = get_gpg_details("/tmp/crt.txt")
                certificatename = "gpg"
            elif 'crl' in results['Name']:
                crldate = get_crl_next_update("/tmp/crt.txt")
                daystoexpire = (crldate - datetime.today()).days
                certificatename = "crl"
            else:
                daystoexpire, certificatename = get_cert_details("/tmp/crt.txt")

            if daystoexpire < 20:
                try:
                    SNS.publish(
                        TargetArn=TOPIC,
                        Subject='Certificate Validation Alerts',
                        Message=json.dumps({
                            'default': 'Cert expires in {} for this domain {}({})'.format(
                                daystoexpire, certificatename, results['Name']
                            )
                            }),
                        MessageStructure='json'
                    )
                except:
                    print("Error Occured while sending msg")
