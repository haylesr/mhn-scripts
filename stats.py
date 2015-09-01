import sys
import os
import re

countries = {}
counter = {}
ips = []
notIdentified = []

totalAttacks = int(os.popen("mongo mnemosyne --quiet --eval \"db.session.count()\"").read())
list = os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('source_ip')\"").read().split(',')

for ip in list:
  ip = re.sub(r'\\n\']','',ip)
  if re.match(r'\d+\.\d+\.\d+\.\d+',ip):
     output = os.popen("geoiplookup "+ip).read()
     #print ip
     #print output
     output = re.sub(r'.*[A-Z]+, ','',output)
     output = re.sub(r'\n','',output)
     if output == "GeoIP Country Edition: IP Address not found":
        notIdentified.append(ip)
     else:
        ips.append(ip)
        countries[ip] = output
        if output in counter:
           counter[output] = counter[output]+1
        else:
           counter[output] = 1
unique = []
for country in countries.values():
  if country not in unique:
    unique.append(country)
print
for country in unique:
  x = 0
  print country + ": "
  print "   Percent of unique IP addresses: " + str(round(counter[country]/float(len(countries)),4)*100) + "%"
  for ip in ips:
     if countries[ip] == country:
        x = x + int(os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'source_ip':'"+ip+"'}).count()\"").read())
  print "   Percent of total attacks: " + str(round(x/float(totalAttacks),4)*100) + "%"
  print "   Total IP addresses: " + str(counter[country])
  #print "   IP Addresses:"
  #for ip,location in countries.items():
     #if location == country:
        #print "      "+ip
  print
print "**Could not identify " + str(len(notIdentified)) + " IPs**"
#for ip in notIdentified:
   #print "   "+ip
print
print "Total attacks: " + str(totalAttacks)
print
print "Unique Countries: " + str(len(unique))
print
print "Unique IP addresses: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('source_ip').length\"").read()
print "Kippo attacks: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'kippo'}).count()\"").read()
print "   Unique usernames: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('auth_attempts.login').length\"").read()
print "   Unique passwords: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('auth_attempts.password').length\"").read()
print "Dionaea attacks: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'dionaea'}).count()\"").read()
print "Glastopf attacks: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'glastopf'}).count()\"").read()
print "Amun attacks: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'amun'}).count()\"").read()
print "p0f attacks: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'p0f'}).count()\"").read()
print "Unique ports attacked: " + os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('destination_port').length\"").read()
print "Malware samples: " + os.popen("mongo mnemosyne --quiet --eval \"db.file.count()\"").read()
