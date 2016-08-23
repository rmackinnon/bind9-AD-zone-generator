#!/usr/bin/python2.7
import argparse
import json
from uuid import uuid4, uuid5, NAMESPACE_DNS
from os import mkdir as OS_MKDIR
from os.path import exists as OS_PATH_EXISTS
from os import stat as OS_STAT

__author__ = 'Rob MacKinnon <rob.mackinnon@gmail.com>'
__copyright__ = "Copyright (c)2015 Rob MacKinnon"
__license__ = "MIT"
__version__ = "0.1.2"

"""
generate-ad-zones v0.1.2
A tool for automagically generating MS Compliant DNS domain records for Kerberos domains on Bind9 DNS hosts.

Released under MIT License, copyright (c)2015 Rob MacKinnon

Sample DNS Records for MS Domain Entries
.					IN	A		${PDC_HOST_IP}
;TXT Record
_kerberos			IN	TXT		"kerberos.${REALM_LC}"
kerberos 			IN	CNAME	${KDC_HOST_FQDN}.

;MS Domain Support
;${TLD}/${REALM_BASE}/_tcp/root.zone
_ldap									IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};
_kerberos								IN	SRV 0 0 88		${KDC_HOST_FQDN[0]};
_kpasswd								IN	SRV 0 0 88		${KDC_HOST_FQDN[0]};
_gc										IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};

;${TLD}/${REALM_BASE}/_udp/root.zone
_ldap									IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};
_kerberos								IN	SRV 0 0 88		${KDC_HOST_FQDN[0]};
_kpasswd								IN	SRV 0 0

;${TLD}/${REALM_BASE}/_sites/root.zone
_ldap._tcp.${SITE_NAME[0]}				IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};
_kerberos._tcp.${SITE_NAME[0]}			IN	SRV 0 0 88		${KDC_HOST_FQDN[0]};
_gc._tcp								IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};

;${TLD}/${REALM_BASE}/_msdcs/dc/root.zone
_ldap._tcp								IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};
_kerberos._tcp							IN	SRV 0 0 88		${KDC_HOST_FQDN[0]};

;${TLD}/${REALM_BASE}/_msdcs/dc/_sites/root.zone
_ldap._tcp.${SITE_NAME}					IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};
_kerberos._tcp.${SITE_NAME[0]}			IN	SRV 0 0 88		${KDC_HOST_FQDN[0]};

;${TLD}/${REALM_BASE}/_msdcs/root.zone
${DSA_GUID}								IN	A	${PDC_HOST_IP}
_ldap._tcp.pdc							IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};

;${TLD}/${REALM_BASE}/_msdcs/gc/root.zone
.										IN	A	${PDC_HOST_IP}
_ldap._tcp								IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};

_ldap._tcp.${SITE_NAME[0]}._sites		IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};
_kerberos._tcp.${SITE_NAME[0]}._sites	IN	SRV 0 0 88		${KDC_HOST_FQDN[0]};

;${TLD}/${REALM_BASE}/_msdcs/domains/root.zone
_ldap._tcp.${DOMAIN_GUID}				IN	SRV 0 0 389		${PDC_HOST_FQDN[0]};
"""


def return_SOA_record(soa_dict, apexZone=None):
    if not "serial-number" in soa_dict:
        _serial = 1
    else:
        _serial = soa_dict["serial"]

    if apexZone is None:
        apexZone = "@"
    # else:
    #     apexZone = "$ORIGIN %s.\n@" % apexZone

    return "$TTL %d\n%s\tIN\tSOA\t%s. %s. (\n" \
           "\t\t\t\t\t\t\t\t%d\t; serial number\n" \
           "\t\t\t\t\t\t\t\t%d\t; refresh\n" \
           "\t\t\t\t\t\t\t\t%d\t; retry\n" \
           "\t\t\t\t\t\t\t\t%d\t; expire\n" \
           "\t\t\t\t\t\t\t\t%d\t; min TTL\n)\n\n" % (soa_dict["default-min-ttl"], apexZone, soa_dict["ns"], soa_dict["admin"],
                                                  _serial, soa_dict["default-refresh"], soa_dict["default-retry"],
                                                  soa_dict["default-expires"], soa_dict["default-min-ttl"])


def return_record(recordType, preTabs, postTabs, record, hostname=None):
    _prefix = ''
    _width = 60
    if hostname is not None:
        _width -= len(hostname)
        _prefix = hostname
    _prefix += " "*_width
    return '%s%sIN\t%s%s%s' % (_prefix, '\t'*preTabs, recordType, '\t'*postTabs, record)


def return_SRV_records(port, fqdn, hostname=None):
    return return_record('SRV', 0, 1, "0 0 %d\t%s." % (port, fqdn), hostname)
    # return "\t\t\t\t\t\tIN\tSRV\t0 0 %d\t%s" % (port, fqdn)


def return_NS_records(host_ip, hostname=None):
    # if hostname is None:
    #     hostname = "@"
    return return_record('NS', 0, 2, host_ip+".", hostname)
    # return "host\t\tIN\tNS\t\t%s" % (host_ip)


def return_A_records(host_ip, hostname=None):
    return return_record('A', 0, 2, host_ip, hostname)
    # return "\t\tIN\tA\t\t%s" % (host_ip)


def return_TXT_records(txt, hostname=None):
    return return_record('TXT', 0, 2, txt, hostname)
    # return "\t\tIN\tTXT\t\t%s" % (txt)


def return_CNAME_records(cname, hostname=None):
    return return_record('CNAME', 0, 2, cname+".", hostname)
    # return "\t\tIN\tCNAME\t%s" % (cname)


def createPath(path):
    # path exits
    try:
        if not OS_PATH_EXISTS(path):
            OS_MKDIR(path)
    except:
        print "Problem creating SRV directory structure, or directory exists: %s" % path
        return False

    # is path writeable
    try:
        path_stat = OS_STAT(path)
        if not path_stat.st_mode >= 600:
            print "Unable to create writable directory '%s'" % path
            return False
    except:
        print "Unable to stat '%s'" % path
        return False
    return True


def createBindConf(zone, fileName):
    return 'zone "%s" in {\n' \
           '   type master;\n' \
           '   file "%s";\n' \
           '};\n' % (zone, fileName)


def writeZoneRecord(soa, path, record):
    try:
        _f = open(path+"/root.zone", mode="w")
    except:
        print "Problem open zone file for: %s" % path
        return False

    try:
        _f.write(soa)
        _f.write(record)

    except:
        print "Unable write to the zone file."
        return False
    _f.close()
    return True


def createSYSVOLStructure(config, dsaGuid):
    # TODO: Future expansion to support SYSVOL structure
    # Directories: domain, staging, staging areas, Sysvol
    # SYSVOL/<fqdn-domainName>/Policies/<gpo-guid>/Gpt.ini
    # SYSVOL/<fqdn-domainName>/Policies/<gpo-guid>/{User,Machine}/
    # domain/
    # domain/Policies
    # domain/scripts
    # staging/domain/
    # staging areas/<fqdn-domainName>
    # Create
    pass


def createDNSRecords(config=None):
    REALM = ".".join((config["realm"], config["realm-tld"])).lower()
    if "domain-guid" not in config:
        DOMAIN_GUID = str(uuid4())
    else:
        DOMAIN_GUID = config["domain-guid"]
    GC_FQDN = config["domain-controllers"][config["sites"][config["global-catalog-location"]]["pdc"]]["fqdn"]
    GC_IP = config["domain-controllers"][config["sites"][config["global-catalog-location"]]["pdc"]]["ip"]
    GC_LOC = config["sites"][config["global-catalog-location"]]["name"]
    KRB_MASTER = config["kerberos-kdc"][config["primary-kdc"]]["fqdn"]

    SOA = return_SOA_record(config["soa"])

    CREATE_ZONE_RECORDS = config['options']['create-zones']

    # open/create output files
    print "//*.%s\n" % REALM
    _record = "%s\n" \
              "%s\n" \
              "%s\n" \
              "%s\n" % (return_A_records(GC_IP),
                        return_TXT_records("kerberos.%s" % REALM, '_kerberos'),
                        return_CNAME_records(KRB_MASTER,'kerberos'),
                        return_CNAME_records(KRB_MASTER, 'kdc'))

    _filePath = config["bind-pri-records"]+"/"+config["realm-tld"]
    if not createPath(_filePath):
        exit(100)

    _filePath = config["bind-pri-records"]+"/".join([config["realm-tld"], config["realm"]])
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = REALM
    print(createBindConf(_zone, _filePath+"/root.zone"))

    #${TLD}/${REALM_BASE}/_tcp/root.zone
    print "//*._tcp.%s\n" % REALM
    _record = ""
    for dc in config["domain-controllers"]:
        _record += "%s\n" % return_NS_records(dc["fqdn"])
    for dc in config["domain-controllers"]:
        _record +='%s\n' % return_SRV_records(389, dc["fqdn"], '_ldap')

    for kdc in config["kerberos-kdc"]:
        _record += '%s\n' % return_SRV_records(88, kdc["fqdn"], '_kerberos')

    _record += '%s\n' \
               '%s\n' \
               '%s\n' % (return_SRV_records(389, GC_FQDN, '_gc'),
                         return_SRV_records(464, KRB_MASTER, '_kpasswd'),
                         return_SRV_records(749, KRB_MASTER, '_kerberos-adm'))

    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_tcp"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)

    _zone = ".".join(("_tcp", REALM))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    #${TLD}/${REALM_BASE}/_udp/root.zone
    print "//*._udp.%s\n" % REALM
    _record = ""
    for dc in config["domain-controllers"]:
        _record += "%s\n" % return_NS_records(dc["fqdn"])

    for dc in config["domain-controllers"]:
        _record += '%s\n' % return_SRV_records(389, dc["fqdn"], '_ldap')

    for kdc in config["kerberos-kdc"]:
        _record += '%s\n' % return_SRV_records(88, kdc["fqdn"], '_kerberos')

    _record += '%s\n' \
               '%s\n' % (return_SRV_records(464, KRB_MASTER, '_kpasswd'),
                                           return_SRV_records(88, KRB_MASTER, '_kerberos-master'))
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_udp"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = ".".join(("_udp", REALM))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    #${TLD}/${REALM_BASE}/_sites/root.zone
    _record = ""

    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_sites"))
    if not createPath(_filePath):
        exit(100)

    for _site in config["sites"]:
        print "//*.%s._sites.%s\n" % (_site["name"], REALM)
        _site_gc = config["domain-controllers"][_site["pdc"]]["fqdn"]

        for dc in _site["domain-controllers"]:
            dcRecord = config["domain-controllers"][dc]
            _record += "%s\n" % return_NS_records(dcRecord["fqdn"])

        for dc in _site["domain-controllers"]:
            dcRecord = config["domain-controllers"][dc]
            _record +='%s\n' % return_SRV_records(389, dcRecord["fqdn"], '_ldap')

        for kdc in _site["kerberos-servers"]:
            kdcRecord = config['kerberos-kdc'][kdc]
            _record +='%s\n' % return_SRV_records(88, kdcRecord["fqdn"], '_kerberos')

        _record += '%s\n' % return_SRV_records(389, _site_gc, '_gc')
        _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_sites", _site["name"]))
        if not createPath(_filePath):
            exit(100)
        _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_sites", _site["name"],
                                                     "_tcp"))
        if CREATE_ZONE_RECORDS:
            if not createPath(_filePath):
                exit(100)
            if not writeZoneRecord(SOA, _filePath, _record):
                exit(101)
        _zone = ".".join(("_tcp", _site["name"], "_sites", REALM))
        print(createBindConf(_zone, _filePath+"/root.zone"))

    #${TLD}/${REALM_BASE}/_msdcs/root.zone
    print "//*._msdcs.%s\n" % REALM
    _record = ""
    for dc in config["domain-controllers"]:
        _record += "%s\n" % return_NS_records(dc["fqdn"])

    for dc in config["domain-controllers"]:
        # dsaGuid          IN A ip
        if "dsaGuid" not in dc:
            _fqdn = str(dc["fqdn"])
            _dsaGuid = str(uuid5(NAMESPACE_DNS, _fqdn))
        else:
            _dsaGuid = dc["dsaGuid"]
        _record += "%s\n" % return_CNAME_records(_dsaGuid, dc["fqdn"])
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = ".".join(("_msdcs", REALM))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    print "//*._tcp.pdc._msdcs.%s\n" % REALM
    _record += '%s\n' % (return_SRV_records(389, GC_FQDN, '_ldap'))
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "pdc"))
    if not createPath(_filePath):
        exit(100)
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "pdc", "_tcp"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = ".".join(("_tcp", "pdc", "_msdcs", REALM))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    #${TLD}/${REALM_BASE}/_msdcs/dc/root.zone
    print "//*.dc._msdcs.%s\n" % REALM
    _record = ""
    for dc in config["domain-controllers"]:
        _record += "%s\n" % return_NS_records(dc["fqdn"])
    for dc in config["domain-controllers"]:
        _record += '%s\n' % return_SRV_records(389, dc["fqdn"], '_ldap')
    for kdc in config["kerberos-kdc"]:
        _record += '%s\n' % (return_SRV_records(88, kdc["fqdn"], '_kerberos'))

    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "dc"))
    if not createPath(_filePath):
        exit(100)
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "dc", "_tcp"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = ".".join(("_tcp", "dc", "_msdcs", REALM))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    #${TLD}/${REALM_BASE}/_msdcs/dc/_sites/_tcp/root.zone
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "dc"))
    if not createPath(_filePath):
        exit(100)
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "dc", "_sites"))
    if not createPath(_filePath):
        exit(100)

    for _site in config["sites"]:
        print "//%s._sites.dc._msdcs.%s\n" % (_site["name"], REALM)
        for dc in _site["domain-controllers"]:
            dcRecord = config["domain-controllers"][dc]
            _record += "%s\n" % return_NS_records(dcRecord["fqdn"])

        for dc in _site["domain-controllers"]:
            dcRecord = config["domain-controllers"][dc]
            _record += "%s\n" % return_SRV_records(389, dcRecord["fqdn"], '_ldap')

        for kdc in _site["kerberos-servers"]:
            kdcRecord = config['kerberos-kdc'][kdc]
            _record += '%s\n' % return_SRV_records(88, kdcRecord["fqdn"], '_kerberos')

        _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "dc", "_sites",
                                                         _site["name"]))
        if not createPath(_filePath):
            exit(100)

        _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "dc", "_sites",
                                                         _site["name"], "_tcp"))
        if CREATE_ZONE_RECORDS:
            if not createPath(_filePath):
                exit(100)
            if not writeZoneRecord(SOA, _filePath, _record):
                exit(101)
        _zone = ".".join(("_tcp", _site["name"], "_sites", "dc", "_msdsc", REALM))
        print(createBindConf(_zone, _filePath+"/root.zone"))

    #${TLD}/${REALM_BASE}/_msdcs/gc/root.zone
    print "//*.gc._msdcs.%s\n" % REALM
    _record = '%s\n' % return_A_records(GC_IP)
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "gc"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = ".".join(("gc", "_msdsc", REALM))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    print "//*._tcp.gc._msdcs.%s\n" % REALM
    for dc in config["domain-controllers"]:
        _record += "%s\n" % return_NS_records(dc["fqdn"])

    _record = '%s\n' % return_SRV_records(389, GC_FQDN, '_ldap')
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "gc", "_tcp"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = ".".join(("_tcp", "gc", "_msdcs", config["realm"], config["realm-tld"]))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    print "//*._tcp.*._sites.gc._msdcs.%s\n" % REALM
    for dc in config["domain-controllers"]:
        _record += "%s\n" % return_NS_records(dc["fqdn"])

    _record = '%s\n' \
              '%s\n' % (return_SRV_records(389, GC_FQDN, '_ldap'),
                        return_SRV_records(88, KRB_MASTER, '_kerberos'))

    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "gc",
                                                     "_sites"))
    if not createPath(_filePath):
        exit(100)
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "gc",
                                                     "_sites", GC_LOC))
    if not createPath(_filePath):
        exit(100)
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"], config["realm"], "_msdcs", "gc",
                                                     "_sites", GC_LOC, "_tcp"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = ".".join(("_tcp", GC_LOC, "_sites", "gc", "_msdcs", config["realm"], config["realm-tld"]))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    #${TLD}/${REALM_BASE}/_msdcs/domains/root.zone
    print "//*._tcp.%s.domains._msdcs.%s\n" % (DOMAIN_GUID,REALM)
    _record = ""
    for dc in config["domain-controllers"]:
        _record += "%s\n" % return_NS_records(dc["fqdn"])

    _record += "%s\n" % return_SRV_records(389, GC_FQDN, '_ldap')
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"],config["realm"],"_msdcs","domains"))
    if not createPath(_filePath):
        exit(100)
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"],config["realm"],"_msdcs","domains",
                                                     DOMAIN_GUID))
    if not createPath(_filePath):
        exit(100)
    _filePath = config["bind-pri-records"]+"/".join((config["realm-tld"],config["realm"],"_msdcs","domains",
                                                     DOMAIN_GUID,"_tcp"))
    if CREATE_ZONE_RECORDS:
        if not createPath(_filePath):
            exit(100)
        if not writeZoneRecord(SOA, _filePath, _record):
            exit(101)
    _zone = ".".join(("_tcp", DOMAIN_GUID, "domains", "_msdcs", config["realm"], config["realm-tld"]))
    print(createBindConf(_zone, _filePath+"/root.zone"))

    return DOMAIN_GUID


def main(configFile):
    try:
        with open(configFile, 'rb') as _jsonFile:
            _config = json.load(_jsonFile)
    except IOError:
        print("!!! Problem opening supplied json config file. Please check and try again.")
        exit(1)

    DOMAIN_GUID = createDNSRecords(_config)
    print("Domain configured, please record your Domain GUID %s" % DOMAIN_GUID)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automated Bind9 zone file compatible with Active Directory')
    parser.add_argument('config', metavar='configJSON', type=str, nargs=1, help='JSON configuration file to load')
    args = parser.parse_args()

    main(args.config[0])
