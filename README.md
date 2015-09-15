nettrack.py
===========
nettrack is a python script to track devices on your local network and store statistics
in a database for displaying on a webpage (or other front-end). It periodically scans
the arp tables

nettrack can be configured with a static list of Bonjour sleep proxy servers and will
update the database when it detects a sleep proxy server is answering ARP requests on
behalf of a sleeping device.

nettrack is based off a perl script called `netinv` developed by Marty Sells that I hacked
up to insert the entries into a database.

Requirements
============

Python 2. There are minimal changes to get it working with Python 3.

Example Usage
=============

Add the following to your crontab.

```# Update macaddress database
*/15 * * * * /home/user/nettrack/nettrack.py
```
