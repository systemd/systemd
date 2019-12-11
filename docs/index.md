---
title: systemd Documentation
---

# systemd Documentation

{% assign by_category = site.pages | group_by:"category" %}
{% assign extra_pages = site.data.extra_pages | group_by:"category" %}
{% assign merged = by_category | concat: extra_pages | sort:"name" %}

{% for pair in merged %}
  {% if pair.name != "" %}
## {{ pair.name }}
{% assign sorted = pair.items | sort:"title" %}{% for page in sorted %}
* [{{ page.title }}]({{ page.url | relative_url }}){% endfor %}
  {% endif %}
{% endfor %}
