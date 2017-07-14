# nps-rras-aclexport
Microsoft NPS RRAS xml export acl/ip rules exporter
I do not have access to any windows machine, so I create only the ipv4 only version. I dont have any ipv6 example.

### Usage
First you have to export NPS rras in xml format.
You will have an XML with fields like this: ``msRASFilter dt:dt="bin.hex" ``
This script converts it to a human readable form so it will be easier to migrate.

```
# cat export.xml|perl export-rras.pl -o <text|csv|grep>
# perl export-rras.pl -f <input xmlfile> -o <text|csv|grep>
```
