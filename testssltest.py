from modules.server.wrappers import testssl as Testssl
import logging
logging.basicConfig(level=logging.DEBUG)
testssl = Testssl.Testssl()

testssl.run(hostname="fbk.eu")