

import os
import sys
import socket
import time
import json
import serial
import datetime
from base64 import b64encode, b64decode


__id__ = 0

def id():
	global __id__
	__id__ = __id__ + 1
	return __id__

def pack(msg):
	return json.dumps(msg).encode("utf8")

def unpack(jsonbytes):
	try:
		return json.loads(jsonbytes.decode("utf8"))
	except Exception as e:
		traceback.print_exc()
		raise e



def test():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	s.bind(('', 8508))


	try:
		msg, addr =s.recvfrom(1024)
		print("received %s from %s"%(str(msg), str(addr)))

		time.sleep(1)

		print("connecting to ", (addr[0], 8507))
		s2.connect((addr[0], 8507))
		print(s2)
		print("send to ", (addr[0], 8507))

		script1 = """
	who;
	mkdir -p /tmp/autotest;
	echo hello autotest > /tmp/autotest/11111;
	date > /tmp/autotest/22222;
	ls /;
	wget http://172.26.66.95/autobuild/openwrt-build-sanity-2017-05-10-16-45-43/openwrt-build-sanity-7620-7610/openwrt-build-sanity-7620-7610-bc4fc4a9-2017-05-10-16-45-44.bin -O /tmp/autotest/firmware.bin;
	sleep 10;
	echo job done;
		"""

		msg = {
			"id": id(),
			"type": "job",
			"data": {
				"type": "shell",
				"data": script1
			},
			"feedback": "yes"
		}

		i = s2.send(pack(msg))
		time.sleep(1)

		i = s2.send(b"pack(msg)")
		time.sleep(1)


	except Exception as e:
		print(e)
		raise e
	finally:
		pass


import subprocess
import threading


def dummy():
	while True:
		print("Hi I'm a dummy thread! My name is "+threading.current_thread().name)
		time.sleep(5)


def check_firmware():
	firmware = {
		"chip" : "mt7621",
		"url" : "http://172.26.66.95/autobuild/openwrt-build-sanity-2017-05-15-01-00-01/openwrt-build-sanity-7621-7615d/openwrt-build-sanity-7621-7615d-31cfb80c-2017-05-15-01-00-02.bin",
	}
	return firmware


def pwm_thread():
	# TODO
	return dummy()

def log_thread():
	# TODO
	# scan COM{n}
	# capture log for each COM, select/poll?
	ser = serial.Serial('COM4', 57600, timeout=60)
	print(ser.name)
	print(ser)
	if not ser:
		return
	while True:
		try:
			print("<"+time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))+"> ", end="")
			print(ser.readline().decode("utf8"), end="")
			#time.sleep(1)
		except serial.SerialException:
			print('SerialException!')
			ser.close()
			#time.sleep(1)


class Logger():
	def __init__(self, port, bitrate=57600, timeout=60, logpath="."):
		self.port = port
		self.bitrate = bitrate
		self.timeout = timeout
		self.logpath = logpath
		self.thread = threading.Thread(target=log_thread, args=[], name="log")
		self.fd = None


	def start_capture(self, mark="<"*32):
		self.fd = serial.Serial('COM4', 57600, 60)
		self.thread.start()
		print(self.fd)
	def stop_capture(self, mark=">"*32):
		pass

class Tester():
	def __init__(self, swinfo):
		self.script_path = "."
		# register pwm
		self.pwm = PowerManager(poweron, poweroff)

		# register log
		self.log = Logger(port="COM1", logpath=".")

	def sanity_check(self):
		# check if target device is online
		for each in test_sets:
			if each["hw"] == firmware["hw"]:
				return True
		else:
			print("the requested hw does not exist!"+firmware["hw"])
			return False


def run_test(testcase):

	pass
	return 

def post_report(testcase, result):
	pass

def tester(test):
	testcases = load_test_case(test.script_path)
	for testcase in testcases:
		try:
			report = run_test(testcase)
			if not report or not report.get("result"):
				print("testcase failed!")
			else:
				print("testcase pass!")
			post_report()
		except Exception as e:
			print(e)
			raise e
		finally:
			pass


class USock():
	def __init__(self):
		self.CHUNK_SIZE = 512
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	def send_ack(self, data, addr):
		ackmsg = {
			id:"",
			"from":"master",
			"to": str(addr),
			"type":"ack",
			"data": data
		}

		if not addr:
			self.sock.sendto(pack(ackmsg), "<broadcast>")
		else:
			self.sock.sendto(pack(ackmsg), addr)

	def wait_ack(self, data, addr):
		while True:
			msg, addr = self.sock.recvfrom(CHUNK_SIZE)
			jmsg = unpack(msg)
			if jmsg and jmsg["type"] == ack and jmsg["data"] == data:
				return True
		return False


	def broadcast(self, data):
		self.sock.sendto(pack(ackmsg), "<broadcast>")

	def sendto(self, data, addr):
		""" send data in CHUNK_SIZE and wait for ack if it is a unicast"""
		tmpdata = data
		retry = 0
		assert addr

		while len(tmpdata) > 0:
			i = min(len(tmpdata), 512)
			self.sock.sendto(tmpdata[0:i], addr)
			self.wait_ack(tmpdata[0:i])
			tmpdata = data[i:]

	def recvfrom(self, bufsize = None):
		msg, addr = self.sock.recvfrom()
		if len(msg) > self.CHUNK_SIZE:
			print("msg size %d > CHUNK_SIZE %d"%(len(msg), self.CHUNK_SIZE))
			return None
		return msg, addr


def msg_thread(sock):
	while True:
		try:
			msg, addr =sock.recvfrom(1024)
			print("received %s from %s"%(str(msg), str(addr)))

			jmsg = unpack(msg)
			if jmsg["type"] == "pong":
				if jmsg["from"] == "agent":
					himsg = {
						"id":1,
						"from":"master",
						"to": str(addr),
						"type":"hi",
					}
					sock.sendto(pack(himsg), addr)
			elif jmsg["type"] == "hi":
				if jmsg["from"] != "agent":
					continue
				if jmsg[""]:
					himsg = {
						"id":1,
						"from":"master",
						"to": str(addr),
						"type":"hi",
					}
					sock.sendto(pack(himsg), addr)
			# message handler
		except Exception as e:
			print(e)
			raise e
		finally:
			pass


#rxsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#txsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

rxsock = USock()
txsock = USock()

pwm_thread = threading.Thread(target=pwm_thread, args=[], name="pwm")
log_thread = threading.Thread(target=log_thread, args=[], name="log")
msg_thread = threading.Thread(target=msg_thread, args=[rxsock], name="msg")

msg_thread.start()
pwm_thread.start()
log_thread.start()

# scan test sets
# this is useful when master get restarted.
test_sets = []


msg = {
	"id":1,
	"from":"master",
	"to":"all",
	"type":"ping",
}

i = txsock.broadcast(pack(msg))


while True:
	time.sleep(1)
	firmware = check_firmware()
	if not firmware:
		continue

	print("firmware update available")
	print(firmware.get("chip"), firmware.get("url"))

	threading.Thread(target=tester, args=[firmware], name="test-mt7620")



#threading.Thread(target=dummy, args=[], name="test-mt7621")
#threading.Thread(target=dummy, args=[], name="test-mt7628")
#threading.Thread(target=dummy, args=[], name="test-mt7622")
#threading.Thread(target=dummy, args=[], name="test-mt7623")






