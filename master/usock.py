import socket
import hashlib
import struct
import threading

class USock():
	"""
	why we need this class?
	1. reliable tx/rx (require ack for each unicast datagram)
	2. sending/receiving by chunk

	TXPORT , send data, receive ack
	RXPORT , receive data, reply ack
	"""
	HEAD_SIZE = 12
	CHUNK_SIZE = 500
	MASTER_TXPORT = 65071
	MASTER_RXPORT = 65072
	AGENT_TXPORT = 65171
	AGENT_RXPORT = 65172
	def __init__(self):
		self.rxseq = 0
		self.txseq = 0
		self.txsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.txsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		self.txsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.txsock.bind(("", self.MASTER_TXPORT))
		self.rxsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.rxsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.rxsock.bind(("", self.MASTER_RXPORT))
		self.__expect_ack = None
		self.lock = threading.Lock()

	def __ack(self, data, addr):
		"""
		Used on rxsock to acknowledge that we've got the data.
		"""
		m = hashlib.md5()
		m.update(data)

		if not addr:
			self.rxsock.sendto(m.digest(), "<broadcast>")
		else:
			self.rxsock.sendto(m.digest(), addr)


	def __wait_ack(self, chksum, addr):
		"""
		Used on txsock to make sure our data has been successfully delievered.
		"""
		self.__expect_ack = chksum
		while True:
			print("expecting ack ", chksum, "from", addr)
			self.txsock.settimeout(3)
			data, sender = self.txsock.recvfrom(self.CHUNK_SIZE)
			self.txsock.settimeout(None)
			if data == chksum:
				print("got ack!", data)
				self.__expect_ack = None
				return True
			else:
				print("invalid ack!", data)
		return False

	def __send(self, data, addr, txsock=None, maxretry = 5):
		""" reliable transmit """
		retry = 0
		txsock = self.txsock if not txsock else txsock
		while retry < maxretry:
			head = struct.pack("Icccccccc", self.txseq, bytes(str(retry).encode("utf-8")),
				b"0",b"0",b"0",b"0",b"0",b"0",b"0")
			txsock.sendto(head+data, addr)
			m = hashlib.md5()
			m.update(head)
			m.update(data)
			if self.__wait_ack(m.digest(), addr):
				self.txseq = self.txseq + len(data)
				return True
			else:
				sleep(1)
				retry = retry + 1
		else:
			print("failed to send data chunk to ", str(addr))
			self.__expect_ack = None
			return False

	def broadcast(self, data):
		"""
		Broadcast data in CHUNK_SIZE. No ACK required.
		"""
		tmpdata = data
		addr = ("<broadcast>", self.AGENT_RXPORT)
		if not self.lock.acquire(True, 10):
			print("failed to acquire sock lock!")
			return False
		print("broadcast data to ", addr)
		while len(tmpdata) > 0:
			i = min(len(tmpdata), self.CHUNK_SIZE - self.HEAD_SIZE)
			if self.txsock.sendto(tmpdata[0:i], addr):
				tmpdata = data[i:]
			else:
				print("broadcast error "+str(addr))
				self.lock.release()
				return False
		print("broadcast done "+str(addr))
		self.lock.release()
		return True

	def sendto(self, data, addr, sock=None):
		""" send data in CHUNK_SIZE and wait for ack if it is a unicast"""
		print("send data to "+str(addr))
		if not self.lock.acquire(True, 10):
			print("failed to acquire sock lock!")
			return False
		tmpdata = data
		assert addr

		while len(tmpdata) > 0:
			i = min(len(tmpdata), self.CHUNK_SIZE - self.HEAD_SIZE)
			if self.__send(tmpdata[0:i], addr, txsock=sock):
				tmpdata = data[i:]
			else:
				print("sendto error "+str(addr))
				self.lock.release()
				return False
		print("send done "+str(addr))
		self.lock.release()
		return True

	def recv(self):
		data, addr = self.rxsock.recvfrom(self.CHUNK_SIZE)
		if len(data) > self.CHUNK_SIZE or len(data) < self.HEAD_SIZE:
			print("invalid data size %d, drop it!"%(len(data), self.CHUNK_SIZE))
			return (None, None)
		self.__ack(data, addr)
		return data, addr

	def recvfrom(self, sender = None):
		data, addr = self.recv()
		if sender and sender != sender:
			print("expecting msg from {0} but got msg from {1}, ignore!".format(str(sender), str(addr)))
			return None
		return data, addr

if __name__ == "__main__":
	print("test usock")
	import json
	sock = USock()
	sock.broadcast(json.dumps({"1":"a","2":"B"}).encode("utf8"))

	sock.sendto(b"are you ok?", ("127.0.0.1", sock.AGENT_RXPORT))

	data, addr = sock.recv()
	print(data, addr)
