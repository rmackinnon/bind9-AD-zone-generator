# Bind9 AD Zone Generator v0.1.2
Copyright (c)2015 by Rob MacKinnon. Released under an MIT license.

## About

This tool was created to automate the creation of Bind v9 compatible zone records containing all required SRV entries for a compatible 2012 R2 Active Direectory domain server with support for Kerberos authenication.
It will create the following records automatically:

SRV Records:
```
_ldap._tcp
_ldap._udp
_kerberos._tcp
_kerberos._udp
_kpasswd._tcp
_kpasswd._udp
_gc._tcp
_ldap._tcp.<SITE_NAME*>._sites
_kerberos._tcp.<SITE_NAME*>._sites
_gc._tcp._sites
_ldap._tcp.dc._msdcs
_kerberos._tcp.dc._msdcs
<DsaGuid>._msdcs
_ldap._tcp.pdc._msdcs
_ldap._tcp.gc._msdcs
_ldap._tcp.<SITE_NAME[0]>._sites.gc._msdcs
_kerberos._tcp.<SITE_NAME[0]>._sites.gc._msdcs
```

TXT Records:
```
_kerberos
kerberos
```

## Configuration

Lets disect the configuration JSON file ...

```
{
```

#### Bind Configuration

###### Bind Zone File Base Directory

Set this field to the base directory of your bind zone records.
```
    "bind-pri-records": "/etc/bind/pri/",
```

###### Zone Record Defaults
Assign all the SOA defaults in this section.  The following keys are required:
- ns: Set the FQDN of the name server for this realm.  This value should be set in the base zone record.
- admin: This string should be the same dot string for a standard responsible administrator for a BIND record.  The example here would map to "root@realm.local"
- default-refresh: Default record refresh rate
- default-retry: Default record retry rate
- default-expires: Default record expiration rate
- default-min-ttl: Default record TTL rate

Optional keys:
- serial: Set the serial number for all records.
```
    "soa": {
        "ns": "ns.realm.local",
        "admin": "root.realm.local",
        "serial": 1,
        "default-refresh": 3600,
        "default-retry": 600,
        "default-expires": 86400,
        "default-min-ttl": 3600,
    },
```

#### Configuring for Kerberos

###### Kerberos Realm Settings

These fields should match your pre-configured Kerberos realm
```
    "realm": "realm",
    "realm-tld": "local",
```

###### Defining Kerberos KDCs

Each dictionary entry should contain the following keys:
- fqdn: The FQDN of the defined KDC/Secondardy KDC
```
    "kerberos-kdc": [
        {"fqdn": "dc.realm.local"}
    ],
```
###### Setting A Primary KDC

Define which index of kerberos-kdc records is the primary KDC of your domain
```
    "primary-kdc": 0,
```

#### Configuring Your Domain

###### Optional: Domain GUID

This setting should be set to the pre-defined domain GUID. If not defined, a random GUID will be assigned to the domain.
```
    "domain-guid": "00000000-0000-0000-00000000",
```

###### Domain Controllers

Domain controllers are defined in the next section.  Each DC should be defined in individual dictionaries.

The following keys are required:
- fqdn: This should reflect the domain controller's fully qualified domain name
- ip: Matching static IP for this domain controller

Optional Keys:
- dsaGuid: Assign a DsaGuid to the server.  If not defined, one will be generated
```
    "domain-controllers": [
        {
          "fqdn": "dc.realm.local",
          "ip": "192.168.0.1"
        }
    ],
```

###### Assigning a Global Catalog
This value should be set to the index of the current Global Catalog server
```
    "global-catalog-location": 0,
```

#### Setting Up Sites
In the next section you will setup the individual sites.  There are some requirements for setting up large organizations with larger that 20 sites.  These consideration should be considered with building large distributes.

Add each site individually in independent dictionaries within the array.  Here are the following required keys:
- name: MSDN denotes the valid character set for this field as: [a-zA-Z0-9-.] See see (Technet Note KB909264)[https://support.microsoft.com/en-us/kb/909264] for more information.
- pdc: Domain controller index ID from the defined "domain-controllers" array.
- domain-controllers: An array containing all DC IDs from the previous domain-controllers section that reside within this site.
- kerberos-servers: An array containing all KDC IDs from the previous kerberos-kdc section that reside within this site.
```
    "sites": [
        {
          "name": "Default-First-Site-Name",
          "pdc": 0,
          "domain-controllers": [0],
          "kerberos-servers": [0]
        }
    ],
```

#### Additional Options
- create-zones: This value should be set to inject zone directly into the bind configuration.  It is not required to generate zone files.
```
    "options": {
        "create-zones": false
    }

That's it.

```
}
```
## Command Line Usage

generate-ad-zones.py <config.json>

## Future TODO

Eventually I'll extend this utility to accept configuration JSON via URL.
