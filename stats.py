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
numUniqueIPs = executeQuery("db.session.distinct('source_ip').length")
numKippoAttacks = executeQuery("db.session.find({'honeypot':'kippo'}).count()")
numUniqueUsernames = executeQuery("db.session.distinct('auth_attempts.login').length")
numUniquePasswords = executeQuery("db.session.distinct('auth_attempts.password').length")
numDionaeaAttacks = executeQuery("db.session.find({'honeypot':'dionaea'}).count()")
numGlastopfAttacks = executeQuery("db.session.find({'honeypot':'glastopf'}).count()")
numAmosAttacks = executeQuery("db.session.find({'honeypot':'amun'}).count()")
numP0fAttacks =  executeQuery("db.session.find({'honeypot':'p0f'}).count()")
numUniquePorts = executeQuery("db.session.distinct('destination_port').length")
numMalwareSamples = executeQuery("db.file.count()")
distinctIPs = executeQuery("db.session.distinct('source_ip')")


for ip in distinctIPs.split(','):
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
