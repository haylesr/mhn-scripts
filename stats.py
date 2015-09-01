import sys
import os
import re
import getopt
import sys
import random

from pyfiglet import figlet_format

#Initialize dictionaries for tracking country specific metrics
countriesByIP = {}
countByCountry = {}

#Initialize lists to track IP addresses
allIP = []
notIdentified = []

#Set usage string to be used for error screens
usage = "Usage: stats.py [Options]"

#Initialize flags to default value of false
verbose = False
veryVerbose = False
geo = False
everything = False

#Initialize verbose levels
geoLevel = 0

fonts = ['big','bulbhead','block','doh','doom','isometric1','isometric2','isometric3','isometric4','larry3d','rectangles','smkeyboard','usaflag']

#Proccess all command line arguments and gracefully exit upon failure
try:
  options, remainder = getopt.getopt(sys.argv[1:],'hgg:a',['geo','geo:','help','all'])
except getopt.GetoptError:
  print usage
  sys.exit(2)

#Process flags
for opt, arg in options:
    if opt in ('-h','-help'):
        print figlet_format('Stats!', font=random.randrange(len(fonts)))
        print usage
        print
        print 'Options:'
        print '     -a --all       Get all metrics'
        print '     -h --help      Print help menu'
        print '     -g --geo       Get geo location'
        sys.exit()
    if opt in ('-g','--geo'):
      geo = True
      if arg:
        geoLevel = arg
      print "geo"
    if opt in ('-a','--all'):
      everything = True
      print "all"

#Execute mongodb query
def executeQuery(query):
  return os.popen("mongo mnemosyne --quiet --eval \""+query+"\"").read()

#Execute OS command
def executeCommand(command):
  return os.popen(command).read()

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
distinctIPList = executeQuery("db.session.distinct('source_ip')").split(',')
distinctCountries = []


for ip in distinctIPList:
  ip = re.sub(r'\\n\']','',ip)
  if re.match(r'\d+\.\d+\.\d+\.\d+',ip):
    country = executeCommand("geoiplookup "+ip)
    country = re.sub(r'.*[A-Z]+, ','',country)
    country = re.sub(r'\n','',country)
    if country == "GeoIP Country Edition: IP Address not found":
      notIdentified.append(ip)
    else:
      allIP.append(ip)
      countriesByIP[ip] = country
      if country in countByCountry:
        countByCountry[country] = countByCountry[country]+1
      else:
        countByCountry[country] = 1
for country in countriesByIP.values():
  if country not in distinctCountries:
    distinctCountries.append(country)

def getCountryStats():
  for country in distinctCountries:
    x = 0
    print country + ": "
    print "   Percent of unique IP addresses: " + str(round(countByCountry[country]/float(len(countriesByIP)),4)*100) + "%"
    for ip in allIP:
      if countriesByIP[ip] == country:
        x = x + int(executeQuery("db.session.find({'source_ip':'"+ip+"'}).count()"))
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
print "Unique countries: " + str(len(distinctCountries))
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