---
layout: post
title:  "My splunk onelines to remember"
date:   2020-12-14 19:59:44 +0100
categories: splunk 4n6 forensics
---
At Kringlecon 2020 was there a splunk objective. Here I have collected some splunks commands that can be used to get knowledge about a splunk instance

Show all indecies:
{% highlight sql linenos %}
| eventcount summarize=false index=* index=_* | dedup index | fields index
{% endhighlight %}

