#!/usr/local/bin/python -B

# nettrack - Track devices on your local network using arp tables and keep stats
#  on them in a database for displaying on a webpage (or other front-end). It will
#  use the NMAP MAC Vendor database to lookup vendor information.
#
# Copyright (c) 2016 Aaron Linville <aaron@linville.org>

import argparse
import MySQLdb
import re
import socket
import subprocess
import sys
import os.path

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

verbose = None

def get_arp_table(sleep_proxy_servers):
    '''Scans the ARP tables and returns a dict of all the entries.'''
    entries = []
    
    cmd = subprocess.Popen('arp -a', shell=True, stdout=subprocess.PIPE)
    for idx, line in enumerate(cmd.stdout):
        if verbose:
            print("Parsing: %s" % (line))
        
        if(idx == 0):
            continue
        
        columns = line.split()
        
        if len(columns) < 4 or len(columns) > 5:
            print("Unexpected arp output: %s" % (line))
            continue
        
        fullhostname = columns[0]
        host = re.sub('\.localnet$', '', fullhostname)
        try:
            ip = socket.gethostbyname(fullhostname)
        except:
            print("Couldn't resolve host: %s" % (fullhostname))
            continue
        
        address = columns[1]
        
        sleeping_entry = False
        
        for server in sleep_proxy_servers:
            if verbose:
                print(server)
            
            # Ascertain if this is a sleep proxy server itself or the sleep proxy
            # server masquerading as a sleeping host.
            if fullhostname == server["host"] and address == server["address"]:
                # This is a the sleep proxy server itself
                sleeping_entry = False
            elif fullhostname != server["host"] and address == server["address"]:
                # This is sleep proxy server respond on a sleeper's behalf
                sleeping_entry = True
        
        entry = {
            "host" : host,
            "ip" : ip,
            "address" : address,
            "netif" : columns[2],
            "expireStr" : columns[3],
            "flags" : columns[4] if len(columns) == 5 else None,
            "sleeping" : sleeping_entry
        }
        
        entries.append(entry)
    
    return entries

def dot_replace(matchobj):
    if matchobj.group(0) == '.':
        return ''
    elif  matchobj.group(0) == ':':
        return ''

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Track devices on your local subnet.")
    parser.add_argument("-v", "--verbose", action="store_true", help = "Verbose output")
    parser.add_argument("-c", "--config", type=argparse.FileType('rb', 0), help = "Config file")
    
    args = parser.parse_args()
    
    config = configparser.SafeConfigParser()
    
    if args.config is not None:
        config.read(args.config.name)
    elif os.path.isfile(os.path.expanduser('~/.nettrack.conf')):
        config.read(os.path.expanduser('~/.nettrack.conf'))
    elif os.path.isfile('/etc/nettrack.conf'):
        config.read('/etc/nettrack.conf')
    else:
        print("Can't find a config file.")
        sys.exit(1)
    
    if args.verbose:
        verbose = True
    
    
    if not (config.has_option("Database", "database") and
            config.has_option("Database", "username") and 
            config.has_option("Database", "password")):
        print("Database config isn't set.")
        sys.exit(1)
    
    
    try:
        db = MySQLdb.connect(db=config.get('Database', 'database'),
                             user=config.get('Database', 'username'),
                             passwd=config.get('Database', 'password'))
        cursor = db.cursor()
    except ValueError as e:
        print("MySQL failed: %s" % e)
        sys.exit(1)
    
    sps_conf = config.items("Sleep Proxy Servers")
    
    sleep_proxy_servers = []
    for entry in sps_conf:
        server = entry[1].split(',')
        if len(server) == 2:
            entry = {
                "host" : server[0].strip(),
                "address" : server[1].strip()
            }
            
            sleep_proxy_servers.append(entry)
        else:
            print("Can't discern host/MAC from %s" % (server))
            continue
    
    macs_lines = []
    
    try:
        mac_db_file = open(config.get('Files', 'macvendordb'),'r')
        macs_lines = mac_db_file.readlines()
    except:
        print("Failed to read the MAC Vendor database.")
    
    entries = get_arp_table(sleep_proxy_servers)
    
    for entry in entries:
        getprefix = re.search('.*([a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}).*', entry["address"], re.IGNORECASE)
        if getprefix is None:
            print("Malformed MAC Address: %s" % (entry["address"]))
            continue
        
        prefix = re.sub(':', dot_replace, getprefix.group(1))[0:6]
        prefixre = re.compile(prefix, re.IGNORECASE)
        
        vendor = "Unknown"
        
        for mac_entry in macs_lines:
            vendor_line = re.search(prefixre, mac_entry)
            if vendor_line:
                vendor = mac_entry[7:].strip()
                break
        
        if verbose:
            print("Host: %s %s" % (entry["host"], "(Sleeping)" if entry["sleeping"] else ""))
            print("       IP: %s" % entry["ip"])
            print("  Address: %s (%s)\n" % (entry["address"], vendor))
        
        if entry["sleeping"]:
            cursor.execute("UPDATE macaddresses "
                        "SET sleeping=1 "
                        "WHERE dns=%s", (entry["host"], ))
        else:
            cursor.execute("REPLACE INTO macaddresses "
                        "(mac, ip, dns, vendor, last, sleeping) "
                        "VALUES (%s, %s, %s, %s, NOW(), 0)",
                        (entry["address"], entry["ip"], entry["host"], vendor))
    
    db.commit()
