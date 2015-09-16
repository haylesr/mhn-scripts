import sys
import os
import re
import getopt
import sys
import random
import json
import operator
import itertools

from pyfiglet import figlet_format
from ascii_graph import Pyasciigraph

#Initialize dictionaries and list for tracking specific metrics
countriesByIP = {}
countByCountry = {}
distinctCountries = []
attacksByCountry = {}

countByUsername = {}
countByPassword = {}
countByPort = {}

#Initialize lists to track IP addresses
allIP = []
notIdentified = []

#Set usage string to be used for error screens
usage = "Usage: stats.py [Options]"

#Initialize flags to default value of false
geo = False
everything = False
honeypots = False
verbose = False
veryVerbose = False
ports = False
address = False
malware = False
credentials = False
usernames = False
passwords = False

fonts = ['big','bulbhead','block','doom','isometric1','isometric3','larry3d','rectangles','smkeyboard']

#Proccess all command line arguments and gracefully exit upon failure
try:
  options, remainder = getopt.getopt(sys.argv[1:],'hvVgapmic',['honeypots','geo','help','all','ports','ip','malware','credentials','usernames','passwords'])
except getopt.GetoptError:
  print usage
  sys.exit(2)

#Process flags
for opt, arg in options:
    if opt in ('--help'):
        print figlet_format('Stats!', font=fonts[random.randrange(len(fonts))])
        print usage
        print
        print 'Options:'
        print '     --help              Print help menu'
        print '     --all               Get all metrics'
        print '     --geo               Get geo location (could take a little while)'
        print '     --honeypots         Separate honepot types'
        print '     --ip                Pull IP addresses'
        print '     --ports             Pull targeted ports'
        print '     --malware           Pull malware'
        print '     --credentials       Pull both usernames and passwords'
        print '     --usernames         Pull usernames'
        print '     --passwords         Pull passwords'
        print '     -v                  Verbose'
        print '     -V                  Very Verbose'
        sys.exit()
    if opt in ('--geo'):
      geo = True
    if opt in ('--all'):
      everything = True
    if opt in ('--honeypots'):
      honeypots = True
    if opt in ('-v'):
      verbose = True
    if opt in ('-V'):
      veryVerbose = True
    if opt in ('--ports'):
      ports = True
    if opt in ('--malware'):
      malware = True
    if opt in ('--ip'):
      addresses = True
    if opt in ('--credentials'):
      credentials = True
    if opt in ('--usernames'):
      usernames = True
    if opt in ('--passwords'):
      passwords = True

#Execute mongodb query
def executeQuery(query):
  return os.popen("mongo mnemosyne --quiet --eval \""+query+"\"").read()

#Execute OS command
def executeCommand(command):
  return os.popen(command).read()

def is_ascii(s):
  return all(ord(c) < 128 for c in s)

totalAttacks = executeQuery("db.session.count()")
distinctIPList = executeQuery("db.session.distinct('source_ip')").split(',')
for ip in distinctIPList:
  ip = re.sub(r'\\n\']','',ip)
  if re.match(r'\d+\.\d+\.\d+\.\d+',ip):
    allIP.append(ip)

def getHoneypots():
  print "Kippo attacks: " + executeQuery("db.session.find({'honeypot':'kippo'}).count()")
  print "Dionaea attacks: " + executeQuery("db.session.find({'honeypot':'dionaea'}).count()")
  print "Glastopf attacks: " + executeQuery("db.session.find({'honeypot':'glastopf'}).count()")
  print "Amun attacks: " + executeQuery("db.session.find({'honeypot':'amun'}).count()")
  print "p0f attacks: " + executeQuery("db.session.find({'honeypot':'p0f'}).count()")

def getMalware():
  print "Malware samples: " + executeQuery("db.session.distinct('attachments.hashes.sha512').length")

  if verbose or veryVerbose:
    print "md5:"
    md5List = executeQuery("db.session.distinct('attachments.hashes.md5')").split(',')
    i = 1
    for malware in md5List:
      print "     "+str(i)+": "+malware
      i = i + 1

def getPorts():
  print "Distinct ports attacked: " + executeQuery("db.session.distinct('destination_port').length")

  if verbose or veryVerbose:
    portList = executeQuery("db.session.aggregate({\$group:{_id:'\$destination_port','count':{\$sum:1}}},{\$sort:{count:-1}},{\$limit:10}).forEach(function(x){printjson(x)})").split('\n')
    for pair in portList:
      match = re.search(r'"_id" : "(.*)", "count" : (\d+) }',pair)
      if match:
        countByPort[match.group(1)] = int(match.group(2))
    print figlet_format('Ports', font='small')
    graph = Pyasciigraph()
    for line in  graph.graph('', sorted(countByPort.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
    print
  else:
    portList = executeQuery("db.session.aggregate({\$group:{_id:'\$destination_port','count':{\$sum:1}}},{\$sort:{count:-1}},{\$limit:10}).forEach(function(x){printjson(x)})").split('\n')
    for pair in portList:
      match = re.search(r'"_id" : "(.*)", "count" : (\d+) }',pair)
      if match:
        countByPort[match.group(1)] = int(match.group(2))
    print figlet_format('Ports ( Top 10 )', font='small')
    graph = Pyasciigraph()
    for line in  graph.graph('', sorted(countByPort.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
    print

def getAddresses():
  print "Distinct IP addresses: " + executeQuery("db.session.distinct('source_ip').length")
  if veryVerbose:
    for ip in allIP:
      print "      "+ip

def getUsernames():
  print "Unique usernames: " + executeQuery("db.session.distinct('auth_attempts.login').length")
  
  if verbose or veryVerbose:
    usernameList = executeQuery("db.session.aggregate([{\$unwind:'\$auth_attempts'},{\$group:{_id:'\$auth_attempts.login','count':{\$sum:1}}},{\$sort:{count:-1}}]).forEach(function(x){printjson(x)})").split('\n')
    for pair in usernameList:
      match = re.search(r'"_id" : "(.*)", "count" : (\d+) }',pair)
      if match:
        countByUsername[match.group(1)] = int(match.group(2))
    print figlet_format('Usernames', font='small')
    graph = Pyasciigraph()
    for line in  graph.graph('', sorted(countByUsername.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
    print
  else:
    usernameList = executeQuery("db.session.aggregate([{\$unwind:'\$auth_attempts'},{\$group:{_id:'\$auth_attempts.login','count':{\$sum:1}}},{\$sort:{count:-1}},{\$limit:10}]).forEach(function(x){printjson(x)})").split('\n')
    for pair in usernameList:
      match = re.search(r'"_id" : "(.*)", "count" : (\d+) }',pair)
      if match:
        countByUsername[match.group(1)] = int(match.group(2))
    print figlet_format('Usernames ( Top 10 )', font='small')
    graph = Pyasciigraph()
    for line in  graph.graph('', sorted(countByUsername.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
    print

def getPasswords():
  print "Unique passwords: " + executeQuery("db.session.distinct('auth_attempts.password').length")

  if verbose or veryVerbose:
    passwordList = executeQuery("db.session.aggregate([{\$unwind:'\$auth_attempts'},{\$group:{_id:'\$auth_attempts.password','count':{\$sum:1}}},{\$sort:{count:-1}}]).forEach(function(x){printjson(x)})").split('\n')
    for pair in passwordList:
      match = re.search(r'"_id" : "(.*)", "count" : (\d+) }',pair)
      if match:
        countByPassword[match.group(1)] = int(match.group(2))
    print figlet_format('Passwords', font='small')
    graph = Pyasciigraph()
    for line in  graph.graph('', sorted(countByPassword.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
    print
  else:
    passwordList = executeQuery("db.session.aggregate([{\$unwind:'\$auth_attempts'},{\$group:{_id:'\$auth_attempts.password','count':{\$sum:1}}},{\$sort:{count:-1}},{\$limit:10}]).forEach(function(x){printjson(x)})").split('\n')
    for pair in passwordList:
      match = re.search(r'"_id" : "(.*)", "count" : (\d+) }',pair)
      if match:
        countByPassword[match.group(1)] = int(match.group(2))
    print figlet_format('Passwords ( Top 10 )', font='small')
    graph = Pyasciigraph()
    for line in  graph.graph('', sorted(countByPassword.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
    print

def getCountryStats():
  for ip in allIP:
    country = executeCommand("geoiplookup "+ip)
    country = re.sub(r'.*[A-Z]+, ','',country)
    country = re.sub(r'\n','',country)
    if country == "GeoIP Country Edition: IP Address not found":
      notIdentified.append(ip)
    else:
      countriesByIP[ip] = country
      if country in countByCountry:
        countByCountry[country] = countByCountry[country]+1
      else:
        countByCountry[country] = 1

  for country in countriesByIP.values():
    if country not in distinctCountries:
      distinctCountries.append(country)

  print "Unique countries: " + str(len(distinctCountries))

  if veryVerbose:
    graph = Pyasciigraph()
    for line in  graph.graph('IP Addresses by Country', sorted(countByCountry.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
  else:
    top10 = {}
    counter = 0
    for country,count in sorted(countByCountry.items(), key=operator.itemgetter(1), reverse=True):
      if counter >= 10:
        break
      top10[country] = count
      counter = counter + 1
    print figlet_format('IP Addresses by Country ( Top 10 )', font='small')
    graph = Pyasciigraph()
    for line in  graph.graph('', sorted(top10.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
  print

  for country in distinctCountries:
    numAttacks = 0
    if veryVerbose: 
      print country + ": "
      print "   Percent of all IP addresses: " + str(round(countByCountry[country]/float(len(countriesByIP)),4)*100) + "%"
    for ip in allIP:
      if ip in countriesByIP:
        if countriesByIP[ip] == country:
          numAttacks = numAttacks + int(executeQuery("db.session.find({'source_ip':'"+ip+"'}).count()"))
    attacksByCountry[country] = numAttacks
    if veryVerbose:
      print "   Percent of all attacks: " + str(round(numAttacks/float(totalAttacks),4)*100) + "%"

    if verbose:
      print "   Total IP addresses: " + str(countByCountry[country])

    if veryVerbose:
      print "   IP Addresses:"
      for ip,location in countriesByIP.items():
        if location == country:
          print "      "+ip
    if verbose or veryVerbose:
      print

  if veryVerbose:
    graph = Pyasciigraph()
    for line in  graph.graph('Attacks by Country', sorted(attacksByCountry.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
  else:
    top10 = {}
    counter = 0
    for country,count in sorted(attacksByCountry.items(), key=operator.itemgetter(1), reverse=True):
      if counter >= 10:
        break
      top10[country] = count
      counter = counter + 1
    print figlet_format('Attacks by Country ( Top 10 )', font='small')
    graph = Pyasciigraph()
    for line in  graph.graph('', sorted(top10.items(), key=operator.itemgetter(1), reverse=True)):
      print(line)
  print    

  if verbose or veryVerbose:
    print "**Could not identify " + str(len(notIdentified)) + " IPs**"
  if veryVerbose:
    for ip in notIdentified:
      print "   "+ip
    print

def main():
  print figlet_format('Stats!', font=fonts[random.randrange(len(fonts))])

  if geo or everything:
    getCountryStats()

  if address or everything:
    getAddresses()

  if ports or everything:
    getPorts()

  if usernames or credentials or everything:
    getUsernames()

  if passwords or credentials or everything:
    getPasswords()

  if honeypots or everything:
    getHoneypots()

  if malware or everything:
    getMalware()

  print "Total attacks: " + str(totalAttacks)

if __name__ == "__main__":
    main()