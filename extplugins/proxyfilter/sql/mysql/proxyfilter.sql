CREATE TABLE IF NOT EXISTS proxies (
id INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
client_id INT(10) unsigned NOT NULL,
service VARCHAR(64) NOT NULL,
ip VARCHAR(15) NOT NULL,
time_add INT(10) UNSIGNED NOT NULL,
PRIMARY KEY (id)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;