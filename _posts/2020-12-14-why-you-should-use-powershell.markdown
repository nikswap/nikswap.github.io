---
layout: post
title:  "Why you should use powershell"
date:   2020-12-14 19:59:44 +0100
categories: windows powershell 4n6 forensics
---
Powershell is great!!!

If you use windows (or linux or mac) can you get powershell. Powershell works with objects instead of raw text like in bash.

Powershell uses CmdLets (Command-Lets). A cmdlet is alwaus on the form: Verb-Noun. Example: Get-Process

Nice cmdlets to remember:
* Get-Help or man to get help. Use -ShowWindow to get it in a nice window
* Get-Member to show the properties and other information about the objects returned from a cmdlets
* Get-Command to show all command avaiable on the system

Here are some nice onelines in powershell that I use from time to time:

Get all processes, select specific and stop thoses processes
{% highlight powershell %}
Get-Process | ? { $_.Name -like '*chrome*' } | Stop-Process
{% endhighlight %}

Read a CSV
{% highlight powershell %}
$csvdata = Import-Csv <csv file>
{% endhighlight %}

Take some data convert to json and save to file
{% highlight powershell %}
$csvdata | ConvertTo-Json | Out-File csv_as_json.json
{% endhighlight %}

Sort and group some data
{% highlight powershell %}
$csvdata | Group -Propery IceCakes | Sort -Property count -Descending
{% endhighlight %}
