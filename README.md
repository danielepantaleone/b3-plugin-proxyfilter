## ProxyFilter Plugin for BigBrotherBot [![BigBrotherBot](http://i.imgur.com/7sljo4G.png)][B3]

### Description

A [BigBrotherBot][B3] plugin will prevent people connected through a proxy to join your server.

### Download

Latest version available [here](https://github.com/danielepantaleone/b3-plugin-proxyfilter/archive/master.zip).

### Installation

* copy the `proxyfilter` folder into `b3/extplugins`
* if you are using `.xml` format for your b3 main configuration file, add to the `plugins` section of your `b3.xml` the following:

  ```xml
  <plugin name="proxyfilter" config="@b3/extplugins/proxyfilter/conf/plugin_proxyfilter.ini" />
  ```
  
* if you are using `.ini` configuration file format for b3 main configuration file, add to the `plugins` section of your `b3.ini` the following:

  ```ini
  proxyfilter: @b3/extplugins/proxyfilter/conf/plugin_proxyfilter.ini
  ```

### Proxy detection

In order to detect proxy connections this plugins make use of the following services:

* [WinMX unlimited](http://winmxunlimited.net/)
* [Geolocation Plugin](https://github.com/danielepantaleone/b3-plugin-geolocation/)

If you know about other proxy detection services offering **free** or **paid** API please leave me a
message on the support forum topic and I will provide support also for those.

### In-game user guide

* **!proxylist** `display the list of available proxy checker services`
* **!proxyservice &lt;service&gt; &lt;on|off&gt;** `enable/disable a proxy checker service`
* **!proxystats** `display statistics about detected proxies`

### Support

If you have found a bug or have a suggestion for this plugin, please report it on the [B3 forums][Support].

[B3]: http://www.bigbrotherbot.net/ "BigBrotherBot (B3)"
[Support]: http://forum.bigbrotherbot.net/plugins-by-fenix/proxyfilter-plugin "Support topic on the B3 forums"

[![Build Status](https://travis-ci.org/danielepantaleone/b3-plugin-proxyfilter.svg?branch=master)](https://travis-ci.org/danielepantaleone/b3-plugin-proxyfilter)
[![Code Health](https://landscape.io/github/danielepantaleone/b3-plugin-proxyfilter/master/landscape.svg?style=flat)](https://landscape.io/github/danielepantaleone/b3-plugin-proxyfilter/master)