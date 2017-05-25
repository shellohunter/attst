
--[[
	This script takes a json bytes as input and output.
]]


local cjson = require("cjson")

print(data)

-- local msg = cjson.decode(data)

local ok, msg = pcall(cjson.decode, data)

if not ok then
	print("unable to decode msg.")
	return -1
end

if not msg.id or not msg.type then
	print("id or type missing, not a valid message!")
	return -1
end

for k,v in pairs(msg) do
	if type(v) ~= type({}) then
		print(k,v)
	end
end




if msg.type == "job" then
	assert(msg.data)
	assert(msg.data.type)
	assert(msg.data.data)
	if msg.data.type == "shell" then
		fp = io.open("/tmp/.autotest.tmp", "w")
		fp:write(msg.data.data)
		fp:close()
		os.execute("sh /tmp/.autotest.tmp")
	end
elseif msg.type == "hi" then
	if msg.from == "master" then
		print("master said hi")
	end
elseif msg.type == "ping" then
	if msg.from == "master" then
		print("master ping")
	end
else
	print("msg type not supported yet!")
end





return "hello!"
