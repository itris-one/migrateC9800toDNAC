# -------------------------------------------------------------------
# Info
# -------------------------------------------------------------------
# Author: Cedric Metzger
# Mail: cmetzger@itris.ch / support.one@itris.ch
# Version: 1.0 / 19. May 2022
# Comment of the author: The greates teacher, failure is - Yoda
# -------------------------------------------------------------------
import argparse
import json
import logging as log
import re
import sys
import warnings
import requests
import pandas as pd
from requests.auth import HTTPBasicAuth
from netmiko import ConnectHandler

# Disable SSL warnings. Not needed in production environments with valid certificates
import urllib3
urllib3.disable_warnings()
# Disable futurewarning caused by pandas.
warnings.simplefilter(action='ignore', category=FutureWarning)
# -------------------------------------------------------------------
# WLC and DNAC
# -------------------------------------------------------------------
# WLC Credentials
WLAN_CONTROLLER = ""  # WLC Name will be set by command line argument or source.txt
USERNAME_WLC = "admin"
PASSWORD_WLC = "Password"

# DNA Center Credentials
BASE_URL = 'https://dnacenter.domain.local' # The BASE URL should NOT have a slash (/) at the end
AUTH_URL = '/dna/system/api/v1/auth/token'
USERNAME_DNAC = "admin"
PASSWORD_DNAC = "Password"


# -------------------------------------------------------------------
# Functions
# -------------------------------------------------------------------


def getwlanconfig(ssidname, wlc):  # Get the wlan profile configuration
    command = "show wlan name " + ssidname
    with ConnectHandler(**wlc) as net_connect:
        output = net_connect.send_command(command)
    return output


def getpolicyprofile(policyname, wlc):  # Get the policy profile configuration
    command = "sh wireless profile policy detailed " + policyname
    with ConnectHandler(**wlc) as net_connect:
        output = net_connect.send_command(command)
    return output


def getservergroup(wlc):  # get the method list used in authorization
    command = "show aaa method-lists authentication"
    with ConnectHandler(**wlc) as net_connect:
        output = net_connect.send_command(command)
    return output


def getradiusserver(groupname, wlc):  # get the radius server used in the method list
    command = "sh radius server-group " + groupname
    with ConnectHandler(**wlc) as net_connect:
        output = net_connect.send_command(command)
    return output


def generatednacjson(oldconfig, oldpolicy, oldservergroup, wlc):  # generate the JSON for the DNAC API
    ssid = re.search(r"(Network\sName\s\(SSID\)[\s]+:\s)(\w.*)", oldconfig).group(2)
    sessiontimeout = re.search(r"\s\s(Session\sTimeout)[\s]+:\s(\w+)", oldpolicy).group(2)
    idletimeout = re.search(r"\s\s(Idle\sTimeout)[\s]+:\s(\w+)", oldpolicy).group(2)

    # find securitystate
    securitystate = "OPEN"
    try:
        dot1xstatus = re.search(r"(802\.1x)[\s]+:\s(\w+)", oldconfig).group(2)
        if dot1xstatus == "Enabled":
            securitystate = "DOT1X"
        if dot1xstatus == "Disabled":
            securitystate = "PSK"
    except AttributeError:
        log.info("Failed to find dot1x, therefore setting it to OPEN")
        securitystate = "OPEN"

    # find client exclusion
    clientexlusionstatebool = False
    try:
        clientexlusionstate = re.search(r"(Exclusionlist[\s]+:\s)(\w+)", oldpolicy).group(2)
        if clientexlusionstate == "ENABLED":
            clientexlusionstatebool = True
    except AttributeError:
        log.info("Failed to find client exclusion, setting clientexlusionstatebool to false")
        clientexlusionstatebool = False
    clientexclusiontimeout = ""
    if clientexlusionstatebool is True:
        clientexclusiontimeout = re.search(r"(Exclusion\sTimeout[\s]+:\s)(\w+)", oldpolicy).group(2)

    # find BSS Max Idle State
    try:
        bssmaxidlestate = re.search(r"(BSS\sMax\sIdle[\s]+:\s)(\w+)", oldconfig).group(2)
        if bssmaxidlestate == "Enabled":
            bssmaxidlestatebool = True
        else:
            bssmaxidlestatebool = False
    except AttributeError:
        log.info("Failed to find bssmaxidlestate, setting it to false")
        bssmaxidlestatebool = False

    # find FT Over-The-DS Mode
    try:
        ftoverthedsstate = re.search(r"(FT\sOver-The-DS\smode[\s]+:\s)(\w+)", oldconfig).group(2)
        if ftoverthedsstate == "Enabled":
            ftoverthedsstatebool = True
        else:
            ftoverthedsstatebool = False
    except AttributeError:
        log.info("Failed to find ft over the ds state bool, setting it to false")
        ftoverthedsstatebool = False

    # find Fast Transition 802.11r
    if securitystate == "OPEN":
        log.info("Securitystate is open, therefore setting fftstatenum to disable")
        ftot1xstateenum = "Disable"
    else:
        try:
            ftstate = re.search(r"(FT\sSupport[\s]+:\s)(\w+)", oldconfig).group(2)
            if ftstate == "Enabled":
                ftot1xstateenum = "Enable"
            elif ftstate == "Adaptive":
                ftot1xstateenum = "Adaptive"
            else:
                ftot1xstateenum = "Disable"
        except AttributeError:
            log.info("Failed to find ftdot1xstate, setting it to Disable")
            ftot1xstateenum = "Disable"

    # find SSID Broadcast
    try:
        broadcastssidstate = re.search(r"(Broadcast\sSSID[\s]+:\s)(\w+)", oldconfig).group(2)
        if broadcastssidstate == "Enabled":
            broadcastssidstatebool = True
        else:
            broadcastssidstatebool = False
    except AttributeError:
        log.info("Failed to find broadcast ssid state, setting it to True")
        broadcastssidstatebool = True

    # mac filtering
    try:
        macfilterstate = re.search(r"(Mac\sFilter\sAuthorization\slist\sname)[\s]+:\s(\w+)", oldconfig).group(2)
        if macfilterstate != "Disabled":
            macfilterstatebool = True
        else:
            macfilterstatebool = False
    except AttributeError:
        log.info("Failed to find mac filter state, setting it to False")
        macfilterstatebool = False

    # protected management frame
    try:
        pmfstate = re.search(r"(PMF\sSupport[\s]+:\s)(\w+)", oldconfig).group(2)
        if pmfstate == "Required":
            pmfstateenum = "Required"
        elif pmfstate == "Optional":
            pmfstateenum = "Optional"
        else:
            pmfstateenum = "Disabled"
    except AttributeError:
        log.info("Failed to find pmf state, setting it to Optional")
        pmfstateenum = "Optional"

    # find 802.11k
    try:
        dot11kstate = re.search(r"(Neighbor\sList[\s]+:\s)(\w+)", oldconfig).group(2)
        dot11kbool = False
        if dot11kstate == "Enabled":
            dot11kbool = True
    except AttributeError:
        log.info("Failed to find dot11k, setting it to False")
        dot11kbool = False

    # find radio policy
    # "radioPolicy": 1, = 2.4 GHz only
    # "radioPolicy": 2, = 5 GHz only
    # "radioPolicy": 0, = Dual band operation(2.4 GHz and 5 GHz)
    try:
        radiopolicystate = re.search(r"(Radio\sPolicy[\s]+:\s)(\w.*)", oldconfig).group(2)
        radiopolicyenum = 0
        if radiopolicystate == "All":
            radiopolicyenum = 0
        elif radiopolicystate == "802.11a only":
            radiopolicyenum = 2
        elif radiopolicystate == "802.11g only":
            radiopolicyenum = 1
        elif radiopolicystate == "802.11bg only":
            radiopolicyenum = 2
        elif radiopolicystate == "802.11ag only":
            radiopolicyenum = 0
    except AttributeError:
        log.info("Failed to find radio policy, setting it to 0/All")
        radiopolicyenum = 0

    # find aaa server
    if securitystate == "DOT1X" or macfilterstatebool is True:
        try:
            dot1xauthenticationlist = re.search(r"(802\.1x\sauthentication\slist\sname)[\s]+:\s(\w+)", oldconfig).group(2)
            dot1xservergroup = re.search(r"(%s.*SERVER_GROUP)\s(\w+)" % dot1xauthenticationlist, oldservergroup).group(2)
            dot1xserver = getradiusserver(dot1xservergroup, wlc)
            dot1xserver = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", dot1xserver)
            j = 0
            for i in dot1xserver:
                log.info("AAA Server found: " + dot1xserver[j])
                j += 1
        except AttributeError:
            log.info("failed to find dot1x server")
            dot1xserver = ""

    # generate 802.1x config
    newcfg = {}
    if securitystate == "DOT1X":
        newcfg = [{
            "groupUuid": "-1",
            "instanceType": "wlan",
            "key": "wlan.info." + ssid,
            "namespace": "wlan",
            "type": "wlan.setting",
            "value": [
                {
                    "authSecServer": None,
                    "authServer": "auth_ise",
                    "authServers": [
                        dot1xserver[0],
                        dot1xserver[1],
                    ],
                    "authType": "wpa2_enterprise",
                    "basicServiceSetClientIdleTimeout": idletimeout,
                    "basicServiceSetMaxIdleEnable": bssmaxidlestatebool,
                    "clientExclusionEnable": clientexlusionstatebool,
                    "clientExclusionTimeout": clientexclusiontimeout,
                    "fastTransition": ftot1xstateenum,
                    "fastTransitionOverTheDistributedSystemEnable": ftoverthedsstatebool,
                    "isBroadcastSSID": broadcastssidstatebool,
                    "isEnabled": True,
                    "isFabric": False,
                    "isFastLaneEnabled": False,
                    "isMacFilteringEnabled": macfilterstatebool,
                    "isSensorPnp": False,
                    "managementFrameProtectionClientprotection": pmfstateenum,
                    "radioPolicy": radiopolicyenum,
                    "neighborListEnable": dot11kbool,
                    "sessionTimeOut": sessiontimeout,
                    "sessionTimeOutEnable": True,
                    "ssid": ssid,
                    "trafficType": "voicedata",
                    "wlanType": "Enterprise"
                }
            ]
        }]

    # generate psk config
    elif securitystate == "PSK":
        newcfg = [{
            "groupUuid": "-1",
            "instanceType": "wlan",
            "key": "wlan.info." + ssid,
            "namespace": "wlan",
            "type": "wlan.setting",
            "value": [
                {
                    "authSecServer": "",
                    "authServer": "",
                    "authServers": [
                    ],
                    "authType": "wpa2_personal",
                    "passphrase": "pskpassphrase",
                    "basicServiceSetClientIdleTimeout": idletimeout,
                    "basicServiceSetMaxIdleEnable": bssmaxidlestatebool,
                    "clientExclusionEnable": clientexlusionstatebool,
                    "clientExclusionTimeout": clientexclusiontimeout,
                    "fastTransition": ftot1xstateenum,
                    "fastTransitionOverTheDistributedSystemEnable": ftoverthedsstatebool,
                    "isBroadcastSSID": broadcastssidstatebool,
                    "isEnabled": True,
                    "isFabric": False,
                    "isFastLaneEnabled": False,
                    "isMacFilteringEnabled": macfilterstatebool,
                    "isSensorPnp": False,
                    "managementFrameProtectionClientprotection": pmfstateenum,
                    "radioPolicy": radiopolicyenum,
                    "neighborListEnable": dot11kbool,
                    "sessionTimeOut": sessiontimeout,
                    "sessionTimeOutEnable": True,
                    "ssid": ssid,
                    "trafficType": "data",
                    "wlanType": "Enterprise"
                }
            ]
        }]

    # generate open config
    elif securitystate == "OPEN":
        newcfg = [{
            "groupUuid": "-1",
            "instanceType": "wlan",
            "key": "wlan.info." + ssid,
            "namespace": "wlan",
            "type": "wlan.setting",
            "value": [
                {
                    "authSecServer": "",
                    "authServer": "",
                    "authServers": [
                    ],
                    "authType": "open",
                    "basicServiceSetClientIdleTimeout": idletimeout,
                    "basicServiceSetMaxIdleEnable": bssmaxidlestatebool,
                    "clientExclusionEnable": clientexlusionstatebool,
                    "clientExclusionTimeout": clientexclusiontimeout,
                    "fastTransition": ftot1xstateenum,
                    "fastTransitionOverTheDistributedSystemEnable": ftoverthedsstatebool,
                    "isBroadcastSSID": broadcastssidstatebool,
                    "isEnabled": True,
                    "isFabric": False,
                    "isFastLaneEnabled": False,
                    "isMacFilteringEnabled": macfilterstatebool,
                    "isSensorPnp": False,
                    "managementFrameProtectionClientprotection": pmfstateenum,
                    "radioPolicy": radiopolicyenum,
                    "neighborListEnable": dot11kbool,
                    "sessionTimeOut": sessiontimeout,
                    "sessionTimeOutEnable": True,
                    "ssid": ssid,
                    "trafficType": "data",
                    "wlanType": "Enterprise"
                }
            ]
        }]

    print(json.dumps(newcfg))
    return json.dumps(newcfg)


def checkforspecialsettings(oldcfg, oldpol, ssidprofilename):
    # ipoverlap
    ipoverlapbool = False
    # if flex is active, ip overlapp is always configured at this project
    try:
        opoverlapstate = re.search(r"(Flex\sCentral\sSwitching[\s]+:\s)(\w+)", oldpol).group(2)
        if opoverlapstate == "DISABLED":
            ipoverlapbool = True
    except AttributeError:
        log.info("Failed to find ipoverlapbool, setting it to False")
        ipoverlapbool = False

    # CCKM
    cckmbool = False
    try:
        cckmboolstate = re.search(r"(CCKM[\s]+:\s)(\w+)", oldcfg).group(2)
        if cckmboolstate == "Enabled":
            cckmbool = True
    except AttributeError:
        log.info("Failed to find cckm, setting it to False")
        cckmbool = False

    # wpa1
    wpa1bool = False
    try:
        wpa1state = re.search(r"(WPA\s\(SSN\sIE\)[\s]+:\s)(\w+)", oldcfg).group(2)
        if wpa1state == "Enabled":
            wpa1bool = True
    except AttributeError:
        log.info("Failed to find wpa1, setting it to False")
        wpa1bool = False

    # peer2peer blocking
    peer2peerbool = False
    try:
        peer2peerstate = re.search(r"(Peer-to-Peer\sBlocking\sAction[\s]+:\s)(\w+)", oldcfg).group(2)
        if peer2peerstate == "Enabled":
            peer2peerbool = True
    except AttributeError:
        log.info("Failed to find peer2peer, setting it to False")
        peer2peerbool = False

    # fastlane
    fastlanebool = False
    try:
        fastlanestate = re.search(r"(Autoqos\sMode[\s]+:\s)(\w+)", oldpol).group(2)
        if fastlanestate != "None":
            fastlanebool = True
    except AttributeError:
        log.info("Failed to find fastlane, setting it to False")
        fastlanebool = False

    # aironet
    aironetbool = False
    try:
        aironetstate = re.search(r"(CCX\s-\sAironetIe\sSupport[\s]+:\s)(\w+)", oldcfg).group(2)
        if aironetstate == "Enabled":
            aironetbool = True
    except AttributeError:
        log.info("Failed to find aironet, setting it to False")
        aironetbool = False

    # dhcp option 82
    dhcpoption82bool = False
    try:
        dhcpopt82state = re.search(r"(DhcpOpt82Enable[\s]+:\s)(\w+)", oldpol).group(2)
        if dhcpopt82state == "ENABLED":
            dhcpoption82bool = True
    except AttributeError:
        log.info("Failed to find dhcp opt 82, setting it to False")
        dhcpoption82bool = False

    # psk configured?
    pskbool = False
    try:
        dot1xstatus = re.search(r"(802\.1x)[\s]+:\s(\w+)", oldcfg).group(2)
        if dot1xstatus != "Enabled":
            pskbool = True
    except AttributeError:
        log.info("Failed to find dot1xstatus, setting it to False")
        pskbool = False

    settings = {
        "ssid": ssidprofilename,
        "ipoverlap": ipoverlapbool,
        "CCKM": cckmbool,
        "wpa1": wpa1bool,
        "peer2peerblocking": peer2peerbool,
        "fastlane": fastlanebool,
        "aironet": aironetbool,
        "dhcpoption82": dhcpoption82bool,
        "presharedkey": pskbool
    }
    print(json.dumps(settings))
    return settings


# DNAC
def gettokendnac():
    log.info("starting to get token for dnac " + BASE_URL + AUTH_URL)
    response = requests.post(BASE_URL + AUTH_URL, auth=HTTPBasicAuth(USERNAME_DNAC, PASSWORD_DNAC), verify=False)
    return response.json()['Token']


def createenterprisessid(payload, authtoken):
    url = BASE_URL + "/api/v1/commonsetting/wlan/-1"
    headers = {
        "x-auth-token": authtoken,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    log.info(response.text)
    response = json.loads(response.text)
    return response['response']['url']


def getstatus(jid, authtoken):
    url = BASE_URL + jid
    headers = {
        "x-auth-token": authtoken,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    response = requests.request("GET", url, headers=headers, verify=False)
    log.info(response.text)
    return response

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""Python script to read
    Example: ReadC9800Config2.py -s'WLANName' -p'PolicyName' -w'WLCName.fqdn.ch' -v -d
    Example: ReadC9800Config2.py -c -v -d
    """)
    parser.add_argument('-s', '--ssid', help='instead of CSV (-c) add a single WLANprofile here')
    parser.add_argument('-p', '--policy', help='instead of CSV (-c) add a single Policyprofile here')
    parser.add_argument('-w', '--wlc', help='instead of CSV (-c) add a single WLC here')
    parser.add_argument('-v', '--verbose', action='store_const', const=True, help='active verbosed logs')
    parser.add_argument('-d', '--dnac', action='store_const', const=True, help='Enable SSID configuration on DNAC')
    parser.add_argument('-c', '--sourcetxt', action='store_const', const=True,
                        help='use a CSV instead of a single WLAN Profile (-s), Policyprofile (-p) and WLC (-w)')
    args = parser.parse_args()

    if args.verbose:  # configure verbose logging
        log.basicConfig(level=log.INFO)
        log.info("verbosed log view")

    if (not args.ssid or not args.policy or not args.wlc) and not args.sourcetxt:  # verifying parameters
        log.error("Exiting. (ssid and policy and wlc) or sourctxt are mandatory.")
        sys.exit(1)

    if args.ssid and args.policy:  # generate dataframe used in the script
        log.info("set df")
        df = pd.DataFrame()
        df2 = {'WP': args.ssid, 'PP': args.policy, 'WLC': args.wlc}
        df = df.append(df2, ignore_index=True)

    if args.sourcetxt:  # using csv as dataframe
        log.info("Starting Batch Production")
        df = pd.read_csv('source.txt')
        print(df)

    df = df.reset_index()  # resetting index for iterating
    dfspecialsettings = pd.DataFrame()  # creating Dataframe for Special Settings
    # iterate through the dataframe in a serial manner
    for index, row in df.iterrows():
        log.info("iteration " + str(row['WP']) + " " + str(row['PP']) + " " + str(row['WLC']))
        log.info("get config for " + str(row['WP']))
        wlc1 = {
            "device_type": "cisco_ios",
            "host": str(row['WLC']),
            "username": USERNAME_WLC,
            "password": PASSWORD_WLC,
        }
        oldcfg = getwlanconfig(str(row['WP']), wlc1)
        oldpol = getpolicyprofile(str(row['PP']), wlc1)
        oldsrvgrp = getservergroup(wlc1)
        log.info("getting config completed")
        log.info("generate DNAC JSON" + str(row['WP']))
        dnacjson = generatednacjson(oldcfg, oldpol, oldsrvgrp, wlc1)
        log.info("json generation completed")
        specialsettings = checkforspecialsettings(oldcfg, oldpol, str(row['WP']))
        dfspecialsettings = dfspecialsettings.append(
            {'ssid': specialsettings['ssid'],
             'ipoverlap': specialsettings['ipoverlap'],
             'CCKM': specialsettings['CCKM'],
             'wpa1': specialsettings['wpa1'],
             'peer2peerblocking': specialsettings['peer2peerblocking'],
             'fastlane': specialsettings['fastlane'],
             'aironet': specialsettings['aironet'],
             'dhcpoption82': specialsettings['dhcpoption82'],
             'presharedkey': specialsettings['presharedkey']},
            ignore_index=True)

        log.info("special settings checked, writing it to specialsettings.csv")
        dfspecialsettings.to_csv('specialsettings.csv')

        if args.dnac:  # generate SSID on dnac
            log.info("starting SSID creation on dnac")
            token = gettokendnac()
            log.info("Token received")
            log.info(token)
            ssidstatus = createenterprisessid(dnacjson, token)
            getstatus(ssidstatus, token)

#################################
