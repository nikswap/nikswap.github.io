---
layout: post
title:  "The wonders of the find command"
date:   2020-12-14 19:59:44 +0100
categories: linux 4n6 forensics
---
More than once have I need some different kind of usage of the find command. Here are some of the greatest usages I have found.

Execute the file command for all files in current and sub directories
{% highlight bash %}
find . -type f -exec file {} \;
{% endhighlight %}

Find all files owned by a specific user
{% highlight bash %}
find . -type f -user <user>
{% endhighlight %}

Find all files with SUID
{% highlight bash %}
find . -type f -perm -4000
{% endhighlight %}

Find all files older than 30 days
{% highlight bash %}
find . -mtime +30
{% endhighlight %}
