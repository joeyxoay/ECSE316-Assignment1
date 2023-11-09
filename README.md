# ECSE316-Assignment1: Network Programming and DNS
By: Joey Koay and Mihail Calitoiu
Date: January 30 2023

Language: We are using Python 3 to write and test our program 

## Running the file 
```python\
Python DnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name
```

- timeout (optional) gives how long to wait, in seconds, before retransmitting an unanswered query
- max-retries(optional) is the maximum number of times to retransmit an unanswered query before giving up. Default value: 3.
- port (optional) is the UDP port number of the DNS server. Default value: 53.
- -mx or -ns flags (optional) indicate whether to send a MX (mail server) or NS (name server) query. At most one of these can be given, and if neither is given then the client should send a type A (IP address) query.
- server (required) is the IPv4 address of the DNS server, in a.b.c.d. format
- name (required) is the domain name to query for.

Example: 
```python\
Python DnsClient.py @8.8.8.8 mcgill.ca
``` 
