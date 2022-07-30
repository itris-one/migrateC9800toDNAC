# Migrate C9800 to DNAC
This script reads the configuration of Catalyst 9800 WLAN Controllers and creates the corresponding SSID on DNAC.
With the use of this script, you can automatically migrate the SSID configuration of a C9800 WLC to DNAC center for automated provisioning of the WLAN to multiple sites depending on your DNAC hierarchy.

The script will show a json with settings DNAC does not support in the terminal. Those settings have to be manually
configured on DNAC with CLI templates as they are not supported by DNACs standard WLAN configuration wizard.
The script is currently checking for: 
- ipoverlap
- CCKM
- WPA1
- Peer-2-Peer Blocking
- Fastlane
- Aironet
- DHCP Option 82
- PSK (not readable from WLC configuration)
 
**Warning:** We do not guarantee a correct migration, always verify the configuration after executing the script

## Prerequisites
- [Python requirements installed](#Install-dependencies)
- [Configure credetials](#Credentials)

## Restrictions
- Works only with IOS based WLCs, AireOS is not supported
- Tested only with IOS 17.3.4c and DNAC 2.2.2.5, use on your on risk

## Installation
### Clone the repository
```
$ git clone https://github.com/itris-one/migrateC9800toDNAC.git
```
**Python version 3** and pip3 is required. Creating a dedicated virtual environment is recommended.

### Creating a virtual environment (optional)

Install the virtualenv package:
```
$ python3 -m pip install virtualenv
```
Create and activate a new virtual environment:
```
$ python3 -m venv ./venv
$ source venv/bin/activate
```

### Install dependencies

```
$ python3 -m pip install -r requirements.txt
```

### Credentials
Edit the script and add your credentials for DNAC and WLC:
```
USERNAME_WLC = "admin"
PASSWORD_WLC = "Password"

# DNA Center Credentials
BASE_URL = 'https://dnacenter.domain.local' # The BASE URL should NOT have a slash (/) at the end
AUTH_URL = '/dna/system/api/v1/auth/token'
USERNAME_DNAC = "admin"
PASSWORD_DNAC = "Password"
```
## How to Use
You can use the script with command line arguments for a single SSID or with a CSV 
to migrate multiple SSIDs from multiple WLCS.

Afterwards the script is ready for execution. To execute without a CSV use:
```
$ python migratec9800toDNAC.py -s WirelessProfile1 -p PolicyProfile1 -w wlc1.domain.local -d
```
To use the script with the prepared CSV (source.txt) use:
```
$ python migratec9800toDNAC.py -c source.txt -d
```

