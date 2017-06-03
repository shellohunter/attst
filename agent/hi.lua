

local cjson = require("cjson")

function __trim(s)
  if s then return (s:gsub("^%s*(.-)%s*$", "%1")) end
end

function get_unique_id()
	local fp = io.open("/tmp/agent.uid", "rb")
	if fp then
		local id = fp:read()
		fp:close()
		return id
	end

	-- generate a new id, using mac + random_number
	math.randomseed(tostring(os.time()):reverse():sub(1,6))
	local id = "000C11234122"..(tostring(math.random()*1000000):sub(1,6))
	fp = io.open("/tmp/agent.uid", "wb")
	fp:write(id)
	fp:close()
	return id
end

function get_cpu( ... )
	local cpu = nil
	local core = 0
	local fp = io.popen("cat /proc/cpuinfo")
	for line in fp:lines() do
		if not cpu then
			_,_,cpu = line:find("model name%s*:(.+)")
		end
		if line:find("processor%s*:") then
			core = core + 1
		end
	end
	print(cpu,core)
	return __trim(cpu), core
end

local msg = {
	id = 1,
	from = "agent",
	to = "all",
	type = "hi",
	data = {
		id = get_unique_id(),
		cpu = get_cpu(),
		core = select(2, get_cpu()),
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

-- print(jmsg)
return jmsg
