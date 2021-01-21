---
layout: post
title:  "Resaerching redirects of dk domains"
date:   2021-01-21 12:00:00 +0100
categories: python web-magic
---
Some malware and malvertising uses redirect from good domains to bad domains.

Using python can we make a database of redirects for further analyzing.

The goal of the project is to identify working domains and which domains redirects to what.

Some findings:
* There are some domains which redirect to the same domains. For instance parked domains or services that buy domains for companies
* Other domains redirect to the .com domain for the company. For instance apple.dk -> apple.com/da
* In one case was there a difference when acccessing from http and from https

The script that scans. This could be done in parallel to maximize the speed.
{% highlight python %}
import requests
import socket
import time
import sqlite3
import sys

conn = sqlite3.connect('malvertasingdb.db')

urls = []

schemas = ["http://","https://"]

no_dns = []
forwardings = {}

headers = {}
headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

def domain_in_db(dom):
    c = conn.cursor()
    rows = c.execute('SELECT id FROM domainnames WHERE domain = ?',(dom,)).fetchone()
    if rows:
        return True
    return False

def add_domain_to_db(dom, sta):
    c = conn.cursor()
    rows = c.execute('SELECT id FROM domainnames WHERE domain = ?',(dom,)).fetchone()
    if domain_in_db(dom):
        return
    stmt = 'INSERT INTO domainnames (domain, http_status) VALUES (?,?)'
    c.execute(stmt,(dom,sta))
    conn.commit()

def add_forwardings_for_domain(dom, forw):
    c = conn.cursor()
    rows = c.execute('SELECT id FROM domainnames WHERE domain = ?',(dom,)).fetchone()
    d_id = rows[0]
    stmt = 'INSERT INTO forwards (domainid, forward_to) VALUES (?,?)'
    c.execute(stmt,(d_id,forw))
    conn.commit()

with open(sys.argv[1]) as f:
    for url in f:
        url = url.strip()
        if domain_in_db(url):
            continue
        for schema in schemas:
            print('[+] CONNECTING TO',schema+url)
            try:
                res = requests.get(schema+url,headers=headers,allow_redirects=False, timeout=5)
                add_domain_to_db(url, res.status_code)
                if res.status_code in [301,302]:
                    add_forwardings_for_domain(url, res.headers['Location'])
            except Exception as e:
                print('[+] NO DNS FOR DOMAIN OR SOME OTHER ERROR',e)
                no_dns.append(schema+url)
                add_domain_to_db(url, 'FAILED TO FETCH')

conn.close()
{% endhighlight %}

Using the following sql can all domains that seems suspicious be found:
{% highlight sql %}
SELECT
        domainnames.added_at
    ,   forwards.added_at
    ,    domain
    ,   forward_to
FROM
    domainnames
    INNER JOIN forwards ON
    domainnames.id = forwards.domainid
WHERE
    INSTR(forward_to,REPLACE(domain,'www.','')) = 0
	AND
    INSTR(forward_to,'.dk') = 0
	AND
    INSTR(forward_to, substr(REPLACE(domain,'www.',''),1,INSTR(REPLACE(domain,'www.',''),'.'))) = 0
	AND
    INSTR(forward_to, 'http') > 0
	AND
    INSTR(forward_to, '?') > 0
ORDER BY
    domainnames.added_at
;
{% endhighlight %}

See the project here: https://github.com/nikswap/malvertising