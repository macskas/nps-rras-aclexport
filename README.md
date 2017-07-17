# nps-rras-aclexport
Microsoft NPS RRAS xml export acl/ip rules exporter
I do not have access to any windows machine, so I created the ipv4-only version. I dont have any ipv6 example.

### Usage
First you have to export NPS rras to xml format.
Then you will have an XML with fields like this: ``msRASFilter dt:dt="bin.hex" ``
This script converts it to a human readable form so it will be easier to migrate to a different vpn solution.

### Problem to solve
Editing RRAS rules is a pain in the ass. Windows gives you a small listbox that you cannot resize. If you have to manage multiple groups with a lot of rules you will want to use solution other than Microsoft RRAS. This is the tool for exporting your stuff so you can migrate.

```
# cat export.xml|perl export-rras.pl -o <text|csv|grep>
# perl export-rras.pl -f <input xmlfile> -o <text|csv|grep>
```

### Example output
```
# cat ../export_test.xml|perl export-rras.pl -o text

- 'Connections to Microsoft Routing and Remote Access server'
         src-ip     src-netmask          dst-ip     dst-netmask   protocol protocol-ext   src-port   dst-port
        0.0.0.0         0.0.0.0         0.0.0.0         0.0.0.0        ANY    -          0          0

- 'TestGroup - 10.2.1.17'
         src-ip     src-netmask          dst-ip     dst-netmask   protocol protocol-ext   src-port   dst-port
        0.0.0.0         0.0.0.0     192.168.3.1 255.255.255.255        TCP    -          0        443
        0.0.0.0         0.0.0.0     192.168.3.1 255.255.255.255        TCP    -          0         22
        0.0.0.0         0.0.0.0 255.255.255.255 255.255.255.255        ANY    -          0          0

```
