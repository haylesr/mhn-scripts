import sys
import os
import re

countriesByIP = {}
countByCountry = {}
ips = []
notIdentified = []

def executeQuery(query):
  return os.popen("mongo mnemosyne --quiet --eval \""+query+"\"").read()

#totalAttacks = int(os.popen("mongo mnemosyne --quiet --eval \"db.session.count()\"").read())
totalAttacks = executeQuery("db.session.count()")
numUniqueIPs = os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('source_ip').length\"").read()
numKippoAttacks = os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'kippo'}).count()\"").read()
numUniqueUsernames = os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('auth_attempts.login').length\"").read()
numUniquePasswords = os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('auth_attempts.password').length\"").read()
numDionaeaAttacks = os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'dionaea'}).count()\"").read()
numGlastopfAttacks = os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'glastopf'}).count()\"").read()
numAmosAttacks = os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'amun'}).count()\"").read()
numP0fAttacks =  os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'honeypot':'p0f'}).count()\"").read()
numUniquePorts = os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('destination_port').length\"").read()
numMalwareSamples = os.popen("mongo mnemosyne --quiet --eval \"db.file.count()\"").read()


for ip in os.popen("mongo mnemosyne --quiet --eval \"db.session.distinct('source_ip')\"").read().split(','):
  ip = re.sub(r'\\n\']','',ip)
  if re.match(r'\d+\.\d+\.\d+\.\d+',ip):
    output = os.popen("geoiplookup "+ip).read()
    output = re.sub(r'.*[A-Z]+, ','',output)
    output = re.sub(r'\n','',output)
    if output == "GeoIP Country Edition: IP Address not found":
      notIdentified.append(ip)
    else:
      ips.append(ip)
      countriesByIP[ip] = output
      if output in countByCountry:
        countByCountry[output] = countByCountry[output]+1
      else:
        countByCountry[output] = 1
unique = []
for country in countriesByIP.values():
  if country not in unique:
    unique.append(country)

def getCountryStats():
  for country in unique:
    x = 0
    print country + ": "
    print "   Percent of unique IP addresses: " + str(round(countByCountry[country]/float(len(countriesByIP)),4)*100) + "%"
    for ip in ips:
      if countriesByIP[ip] == country:
        x = x + int(os.popen("mongo mnemosyne --quiet --eval \"db.session.find({'source_ip':'"+ip+"'}).count()\"").read())
    print "   Percent of total attacks: " + str(round(x/float(totalAttacks),4)*100) + "%"
    print "   Total IP addresses: " + str(countByCountry[country])
    #print "   IP Addresses:"
    #for ip,location in countriesByIP.items():
      #if location == country:
        #print "      "+ip
    print
  print "**Could not identify " + str(len(notIdentified)) + " IPs**"
  #for ip in notIdentified:
    #print "   "+ip

print
print "Total attacks: " + str(totalAttacks)
print
print "Unique countries: " + str(len(unique))
print
print "Unique IP addresses: " + str(numUniqueIPs)
print "Kippo attacks: " + str(numKippoAttacks)
print "   Unique usernames: " + str(numUniqueUsernames)
print "   Unique passwords: " + str(numUniquePasswords)
print "Dionaea attacks: " + str(numDionaeaAttacks)
print "Glastopf attacks: " + str(numGlastopfAttacks)
print "Amun attacks: " + str(numAmosAttacks)
print "p0f attacks: " + str(numP0fAttacks)
print "Unique ports attacked: " + str(numUniquePorts)
print "Malware samples: " + str(numMalwareSamples)
