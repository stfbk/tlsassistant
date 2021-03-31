# move this file to the root folder to make it work.
from modules.server.wrappers.testssl import Testssl
import logging

logging.basicConfig(level=logging.DEBUG)
testssl = Testssl()
input("Pause before normal run")
print(testssl.run(hostname="fbk.eu"))
input("Pause to second run (should return results)")
print(testssl.run(hostname="fbk.eu"))
input("Pause to third run (should return results)")
print(testssl.run(hostname="fbk.eu", force=False))
input("Pause to fourth run (should return results)")
print(testssl.run(hostname="fbk.eu", one=True))
input("Pause to fifth run (should redo the scan with --ip one removed)")
print(testssl.run(hostname="fbk.eu", force=True, one=False))
input("Pause to sixth run (should redo the scan, because IP !=Hostname)")
print(testssl.run(hostname="217.77.80.35", one=True))
