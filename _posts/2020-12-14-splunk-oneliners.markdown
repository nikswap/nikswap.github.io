---
layout: post
title:  "My splunk onelines to remember"
date:   2020-12-14 19:59:44 +0100
categories: splunk 4n6 forensics
---
At Kringlecon 2020 was there a splunk objective. Here I have collected some splunks commands that can be used to get knowledge about a splunk instance

Show all indecies:
{% highlight fsharp %}
| eventcount summarize=false index=* index=_* | dedup index | fields index
{% endhighlight %}

Show fields for index:
{% highlight fsharp %}
index=<index name> | stats values(*) AS * | transpose | table column | rename column AS Fieldnames
{% endhighlight %}

Count indexes:

See more when I make a write up of what I solved in Holiday Hack 2020
