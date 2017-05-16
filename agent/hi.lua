

local cjson = require("cjson")


local msg = {
	id = 1,
	from = "agent",
	to = "all",
	type = "hi",
	data = {
		cpu = "xeon",
		core = "",
		memory = "",
		memuse = "",
		wifi = "",
		os = "",
		sysinfo = {
			os = "linux",
			distributtion = "centos 7",
			kernel = "3.10.123",
		},

		intefaces = {
			{
				type = "eth",
				mac = "AA:BB:CC:DD:EE",
				ifname = "eno1",
				status = "up",
				ip = "192.168.4.1",
				gateway = "",
			},
			{
				type = "eth",
				mac = "00:0C:CC:DD:EE",
				ifname = "eno2",
				status = "up",
				ip = "172.26.121.133",
				gateway = "172.26.121.254"
			}
		},
	}
}

local ok, jmsg = pcall(cjson.encode, msg)

print(jmsg)
return jmsg
