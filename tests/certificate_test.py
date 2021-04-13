# move this file to the root folder to make it work.
from modules.server.wrappers.certificate import Certificate
import logging
from pprint import pprint

logging.basicConfig(level=logging.DEBUG)
cert = Certificate()

pprint(cert.run(hostname='fbk.eu'))
input("Test 1 ok, test2, press a key")
pprint(cert.run(hostname='https://www.fbk.eu'))
input("Test 2 ok, test3, press a key")
pprint(cert.run(hostname='https://www.fbk.eu', force=True)['www.fbk.eu'])
