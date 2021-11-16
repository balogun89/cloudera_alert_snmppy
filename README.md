# Prerequisits
Install pysnmp
```
python -m pip install --upgrade install pysnmp
```
One will need to download your Cloudera installation MIB file
```
wget https://[Cloudera hostname]/static/snmp/cm.mib
```
Or one published in Cloudera documentation
```
wget https://docs.cloudera.com/documentation/other/shared/cm.mib.txt -O cm.mib
```
And place it on the filesystem

Verify that there are generic set of MIBs is present on the system, if not install `snmp-mibs-downloader`
```
sudo [apt|yum] install snmp-mibs-downloader
```
Convert Cloudera MIB to the form acepted by `pysnmp`
```
mibdump.py --debug borrower --generate-mib-texts --mib-source /usr/share/snmp/mibs --mib-source . cm
```

# Bugs
There is a bug in latest released pysnmp (4.4.12)
In the pysnmp/smi/rfc1902.py line 306 should like
```
def resolveWithMib(self, mibViewController, ignoreErrors=True):
```