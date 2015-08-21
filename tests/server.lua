#!/usr/bin/env lua

local cyrussasl = require "cyrussasl"
local argparse = require "argparse"
local inspect = require "inspect"
local socket = require "socket"
local io = require "io"
local os = require "os"

function receiveAndDecode(c)
   l, e = c:receive()
   l = l:sub(4) -- strip off leading "C: "
   return cyrussasl.decode64(l)
end

function encodeAndSend(c, s)
   b64 = cyrussasl.encode64(s)
   c:send("S: " .. b64 .. "\n")
end

function main()
   local args = parseargs()

   local host = "*"
   local port = args['port']

   cyrussasl.server_init("server.lua")

   local ctx = cyrussasl.server_new(args['service'], nil, args['realm'], nil, nil)
   cyrussasl.setssf(ctx, 0, 0xffffffff)

   local c = createSocketAndListen(host, port)

   local mechslist = args['mech']
   if (not mechslist) then
      mechslist = cyrussasl.listmech(ctx, 
				     nil, -- ext_authid
				     nil, -- prefix
				     " ", -- separator
				     nil -- suffix
				  )
   end

   print("Sending mechslist " .. mechslist)
   data = mechslist
   
   -- Loop over the SASL steps until we get SASL_OK (or an error)
   local isFirstRun = true
   local e
   repeat
      encodeAndSend(c, data)

      data = receiveAndDecode(c)
      if (isFirstRun) then
	 -- For the first run, we have to call server_start
	 isFirstRun = false

	 -- Have to separate the MECH\0data
	 pos = data:find("\000")
	 mech = ""
	 if (pos > 0) then
	    mech = data:sub(1,pos-1)
	    data = data:sub(pos+1)
	 end
	 
	 print ("Chosen mech is " .. mech)

	 e, data = cyrussasl.server_start( ctx,
					   mech,
					   data )
	 if (e ~= cyrussasl.SASL_OK and
	     e ~= cyrussasl.SASL_CONTINUE) then
	    print("Error: " .. e)
	    print(tostring(cyrussasl.get_message(ctx)))
	    os.exit(1)
	 end
      else
	 -- For subsequent runs, we call server_step

	 e, data = cyrussasl.server_step( ctx,
					  data )

      end
   until (e ~= cyrussasl.SASL_CONTINUE)

   print("All done. Final error code: " .. e)
   if (e ~= cyrussasl.SASL_OK) then
      print(tostring(cyrussasl.get_message(ctx)))
   else
      print("SASL get_username(): " .. cyrussasl.get_username(ctx))
      print("SASL get_authname(): " .. cyrussasl.get_authname(ctx))

      print("SASL_USERNAME: "     .. cyrussasl.getprop(ctx,cyrussasl.SASL_USERNAME ))
      print("SASL_SSF: "          .. cyrussasl.getprop(ctx,cyrussasl.SASL_SSF      ))
      print("SASL_MAXOUTBUF: "    .. cyrussasl.getprop(ctx,cyrussasl.SASL_MAXOUTBUF))
      print("SASL_DEFUSERREALM: " .. tostring(cyrussasl.getprop(ctx,cyrussasl.SASL_DEFUSERREALM)) )
      print("SASL_IPLOCALPORT: "  .. tostring(cyrussasl.getprop(ctx,cyrussasl.SASL_IPLOCALPORT )) )
      print("SASL_IPREMOTEPORT: " .. tostring(cyrussasl.getprop(ctx,cyrussasl.SASL_IPREMOTEPORT)) )
      print("SASL_SERVICE: "      .. tostring(cyrussasl.getprop(ctx,cyrussasl.SASL_SERVICE     )) )
      print("SASL_SERVERFQDN: "   .. tostring(cyrussasl.getprop(ctx,cyrussasl.SASL_SERVERFQDN  )) )
      print("SASL_AUTHSOURCE: "   .. tostring(cyrussasl.getprop(ctx,cyrussasl.SASL_AUTHSOURCE  )) )
      print("SASL_MECHNAME: "     .. tostring(cyrussasl.getprop(ctx,cyrussasl.SASL_MECHNAME    )) )
      print("SASL_PLUGERR: "      .. tostring(cyrussasl.getprop(ctx,cyrussasl.SASL_PLUGERR     )) )
   end

end

function parseargs()
   local parser = argparse("server.lua", "Sample SASL server")
   parser:option("-p --port", "port", "12345"):args("1"):count("1"):show_default(true)
   parser:option("-m --mech", "mech"):args("1")
   parser:option("-s --service", "service", "host"):args("1"):show_default(true)
   parser:option("-r --realm", "realm"):args("1")

   return parser:parse()
end

function createSocketAndListen(host, port)
   print("Binding to host '" ..host.. "' and port " ..port.. "...")
   local s = assert(socket.bind(host, port))
   local i, p   = s:getsockname()
   assert(i, p)
   print("Waiting connection from client on " .. i .. ":" .. p .. "...")
   local c = assert(s:accept())

   print("Connected.")
   return c
end

main()
os.exit(0)
