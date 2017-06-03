#!/usr/local/bin/python3

import os
import sys
import socket
import time
import json
import serial
import datetime
import sched
from base64 import b64encode, b64decode
import hashlib
import traceback
import subprocess
import threading
import urllib.request


from usock import USock
from testcase import TestCase



def dict2json(msg):
	return json.dumps(msg).encode("utf8")

def json2dict(jsonbytes):
	try:
		return json.loads(jsonbytes.decode("utf8"))
	except Exception as e:
		traceback.print_exc()
		raise e


class Master(object):
	"""test master!"""
	def __init__(self, arg = None):
		super(Master, self).__init__()
		self.arg = arg
		self.agents = []
		self.sock = USock()
		self.msg_thread = threading.Thread(target=self.rx_thread, args=[self], name="rx_thread")

	def run(self):
		self.msg_thread.start()

		# ping all partners, we will handle the responses in msg_thread
		msg = {
			"id":1,
			"from":"master",
			"to":"all",
			"type":"ping",
		}
		print("ping all partners!")
		self.sock.broadcast(dict2json(msg))

		# looping until the end of the world
		while True:
			time.sleep(10)

			# we review test agents every 30s to check if they are still alive.
			print("I'm the master, now review all my %d agents!"%(len(self.agents)))
			for agent in self.agents:
				if not self.ping(agent):
					if agent.noreply < agent.lost:
						print("agent {0} not responding! retry {1}".format(str(agent), agent.noreply))
						agent.noreply = agent.noreply + 1
					else:
						print("we lost agent {0}!".format(str(agent)))
						self.agents.remove(agent)
				else:
					print("agent {0} goes well.".format(str(agent)))

	def ping(self, agent = None):
		targets = [agent] if agent else self.agents
		for target in targets:
			msg = {
				"id":1,
				"from":"master",
				"to": str(agent.addr),
				"type":"ping",
			}

			if self.sock.sendto(dict2json(msg), (target.addr[0], USock.AGENT_RXPORT)):
				return True
			else:
				return False

	@staticmethod
	def job_thread(master):
		while True:
			print("msg thread!")
			sleep(10)



	@staticmethod
	def rx_thread(master):
		while True:
			print("msg thread!")
			try:
				msg, addr = master.sock.recv()
				print("received %s from %s"%(str(msg), str(addr)))

				jmsg = json2dict(msg)
				if jmsg["type"] == "pong":
					if jmsg["from"] == "agent":
						himsg = {
							"id":1,
							"from":"master",
							"to": str(addr),
							"type":"hi",
						}
						master.sock.sendto(dict2json(himsg), addr)
				elif jmsg["type"] == "hi":
					if jmsg["from"] != "agent":
						continue
					if True: #jmsg[""]:
						himsg = {
							"id":1,
							"from":"master",
							"to": str(addr),
							"type":"hi",
						}
						print("got hi msg from agent %s@%s "%(jmsg["data"]["id"], addr))
						print("say hi to agent ", addr[0], USock.AGENT_RXPORT)
						master.sock.sendto(dict2json(himsg), (addr[0], USock.AGENT_RXPORT))


						for agent in master.agents:
							if agent.id == jmsg["data"]["id"]:
								# already have it
								print("a known agent "+jmsg["data"]["id"])
								break
						else:
							# add new agent
							newagent = Agent(addr)
							newagent.id = jmsg["data"]["id"]
							print(newagent)
							print("we got an new agent {0}".format(str(newagent)))
							master.agents.append(newagent)

				# message handler
			except Exception as e:
				print(e)
				raise e
			finally:
				pass


class Logger():
	def __init__(self, dev, bitrate=57600, timeout=60, logpath="."):
		try:
			self.dev = dev
			self.bitrate = bitrate
			self.timeout = timeout
			self.logpath = logpath
			self.thread = None #threading.Thread(target=log_thread, args=[], name="log")
			self.fd = None
		except Exception as e:
			print("Failed to create Logger", e)

	def start_capture(self, mark="<"*32):
		self.fd = serial.Serial('COM4', 57600, 60)
		self.thread.start()
		print(self.fd)
	def stop_capture(self, mark=">"*32):
		pass


class PowerManager():
	"""This class manipulate power-management"""
	def __init__(self, baseurl = "http://10.10.100.254"):
		try:
			self.baseurl = baseurl
		except Exception as e:
			print("Failed to create PowerManager", e)

	def __request(self, url):
		username = "admin"
		password = "admin"

		if url.startswith("/"):
			full_url = self.baseurl + url
		elif url.startswith("http"):
			full_url = url
		else:
			print("invalid url %s"%(url))
			return

		auth_handler = urllib.request.HTTPBasicAuthHandler()
		auth_handler.add_password(realm="USR-IO88", uri=full_url, user=username, passwd=password)
		opener = urllib.request.build_opener(auth_handler)
		urllib.request.install_opener(opener)
		f = urllib.request.urlopen(full_url)
		print(f.read(100).decode('utf-8'))

	def power_down(self):
		self.__request("/httpapi.json?&CMD=UART_WRITE&UWHEXVAL=0")

	def power_on(self):
		self.__request("/httpapi.json?&CMD=UART_WRITE&UWHEXVAL=1")



class Agent():
	"""docstring for Agent"""
	def __init__(self, addr):
		try:
			self.addr = addr
			self.pwm = PowerManager()
			self.logger = Logger("/dev/ttyS1")
			self.name = ""
			self.noreply = 0 # if agent no responding, retry++.
			self.lost = 5 # if retry > lost, we lost the agent. remove it.
			self.id = str(addr) # every agent has an unique id.
		except Exception as e:
			print("Failed to create Agent.", e)

	def execute(self, cmd):
		"""send cmd to agent, the agent will execute it and return result"""
		status = True,
		result = "Mission completed."
		return status, result

	def reboot(self):
		ret, str = self.execute("reboot")
		print(ret, str)

	def power_down(self):
			self.pwm.power_down()

	def power_on(self):
			self.pwm.power_on()




if __name__ == '__main__':
	master = Master()
	master.run()
