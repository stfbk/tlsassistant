from modules.server.wrappers.https_hsts import Https

https = Https()

print(https.run(hostname="https://fbk.eu", type=https.HTTPS))
print(https.run(hostname="https://www.fbk.eu", type=https.HSTSSET))
print(https.run(hostname="http://www.fbk.eu", type=https.SERVERINFO))
print(https.run(hostname="http://www.fbk.eu", type=https.HSTSPRELOAD))

input("Next run should fail by TypeError")
try:
    https.run(hostname="https://fbk.eu", type="testeroni")
except Exception as e:
    print(e)

input("Next run should fail by missing hostname")
try:
    https.run(type=https.HTTPS)
except Exception as e:
    print(e)

input("Next run should fail by missing type")
try:
    https.run(hostname="https://fbk.eu")
except Exception as e:
    print(e)
