nettrack.py
===========
nettrack is a python script to track devices on your local network and store statistics
in for displaying on a webpage (or other front-end). It periodically scans
the arp tables, looks up the vendor information (Organizationally Unique Identifiers -
OUIs) and logs it in the database.

nettrack can be configured with a static list of Bonjour sleep proxy servers and will
update the database when it detects a sleep proxy server is answering ARP requests on
behalf of a sleeping device.

nettrack is based off a perl script called `netinv` developed by Marty Sells that I hacked
up to insert the entries into a database.

Requirements
============

* Python 3. There are minimal changes to get it working with Python 2.
* (Recommended) The [NMAP MAC Vendor Database](https://svn.nmap.org/nmap/nmap-mac-prefixes). Typically installed in `/usr/local/share/nmap-mac-prefixes`

Database Schema
===============

```sql
CREATE TABLE `macaddresses` (
  `mac` varchar(17) NOT NULL,
  `ip` varchar(39) NOT NULL,
  `dns` varchar(64) NOT NULL,
  `vendor` varchar(256) NOT NULL,
  `last` datetime NOT NULL,
  `sleeping` tinyint(1) NOT NULL,
  PRIMARY KEY (`mac`)
)
```

Example Usage
=============

Add the following to your crontab.

```Bash
# Update macaddress database
*/15 * * * * /home/user/nettrack/nettrack.py -c /path/to/config.conf
```
