#!/usr/bin/env lua

local cyrussasl = require "cyrussasl"
local argparse = require "argparse"
local inspect = require "inspect"
local socket = require "socket"
local io = require "io"
local os = require "os"


function receiveAndDecode(c)
   l, e = c:receive()
   l = l:sub(4) -- strip off leading "S: "
   data = cyrussasl.decode64(l)
   return data
end

function main()
   local args = parseargs()
   
   cyrussasl.client_init()   

   print("connecting to server " .. args['server'] .. " on port " .. args['port'])
   c = assert(socket.connect(args['server'], args['port']))   

   -- Initialize sasl client
   ctx = cyrussasl.client_new("host", args['server'], nil, nil)
   cyrussasl.setssf(ctx, 0, 0xffffffff)

   if (args['user']) then
      print("setting user to " .. args['user'])
      cyrussasl.set_username(ctx, args['user'])
   end

   -- Begin looping over SASL iterations until AuthN succeeds or fails
   local isFirstRun = true
   local e
   repeat
      data = receiveAndDecode(c)

      if (isFirstRun) then
	 -- For the first run, we negotiate the mechanism and call client_start
	 isFirstRun = false
	 print("Server advertises mechlist " .. data)
	 if (args['mech']) then
	    print("... but we want to force mechlist " .. args['mech'])
	    data = args['mech']
	 end

	 e, data, mech = cyrussasl.client_start(ctx, data)
	 if (e ~= cyrussasl.SASL_OK and
	     e ~= cyrussasl.SASL_CONTINUE) then
	    print ("Error: " .. e)
	    print(tostring(cyrussasl.get_message(ctx)))
	    os.exit(1)
	 end
	 print("Choosing mech: " .. mech)
	 
	 -- prepend our chosen mech and a NUL
	 b64 = cyrussasl.encode64(mech .. "\000" .. data)
	 c:send("C: " .. b64 .. "\n")
      else
	 -- For subsequent runs, we continue to call client_step
	 e, data = cyrussasl.client_step(ctx, data)
	 b64 = cyrussasl.encode64(data or "")
	 c:send("C: " .. b64 .. "\n")
	 if (e ~= cyrussasl.SASL_OK and
	     e ~= cyrussasl.SASL_CONTINUE) then
	    print ("Error: " .. e)
	    print(tostring(cyrussasl.get_message(ctx)))
	    os.exit(1)
	 end
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
   local parser = argparse("client.lua", "Sample SASL client")
   parser:option("-s --server", "Server name"):args("1"):count("1")
   parser:option("-p --port", "port", "12345"):args("1"):count("1"):show_default(true)
   parser:option("-m --mech", "mech"):args("1")
   parser:option("-u --user", "user"):args("1")

   return parser:parse()
end

main()
os.exit(0)
