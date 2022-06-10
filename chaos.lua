-- Chaosnet dissector for Wireshark, based on AMS hack for Chaos-over-UDP
-- Install in ~/.config/wireshark/plugins (for Linux or macOS).

-- To show Chaosnet packets on Ethernet
-- sudo tshark -O chaos ether proto 0x804
-- To skip all RUT packets (assuming ether header length 14):
-- sudo tshark -O chaos ether proto 0x804 and ether[15] != 8

-- To show only Chaos-over-IP packets (IP protocol 16):
-- sudo tshark -O chaos ip proto 16
-- To show only a specific host, and skip all RUT packets (assuming IP header length 20):
-- sudo tshark -O chaos ip proto 16 and ip host 10.0.1.73 and ip[21] != 8

-- To show only Chaos-over-UDP packets (normally UDP port 42042):
-- sudo tshark -O chaos udp port 42042
-- To show only a specific host, and skip all RUT packets (assuming UDP header length 8+chudp hdr 4):
-- sudo tshark -O chaos udp port 42042 and host 10.0.1.73 and udp[12] != 8

-- Example combination:
-- sudo tshark -O chaos \(ether proto 0x804 and ether[15] != 8\) or \(ip proto 16 and ip[21] != 8\)

-- To see less detail, skip "-O chaos".

-- For the Wireshark lua stuff, see https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html

chaos = Proto("chaos", "Chaosnet")
chudp = Proto("chudp", "Chaos-over-UDP")

local CHAOS_HDR_LEN = 16

local ef_too_short = ProtoExpert.new("chaos.too_short.expert", "Packet too short", expert.group.MALFORMED, expert.severity.ERROR)
chaos.experts = { ef_too_short }

-- Chaos opcode names
local opc_names = { "RFC", "OPN", "CLS", "FWD", "ANS", "SNS", "STS",
       "RUT", "LOS", "LSN", "MNT", "EOF", "UNC", "BRD" }

-- Parse a BRD packet's subnet mask, returning the number of nets in it, and the list of subnetwork numbers
function parse_subnet_mask(tvb, len)
   -- lua is a pretty ghastly language, isn't it?
   local nets = {}
   local nnets = 0
   for i=0,len-1 do
      for j=0,7 do
	 local r = tvb(i,1):int()
	 if r % (2^j + 2^j) >= 2^j then -- see http://lua-users.org/wiki/BitwiseOperators
	    nets[nnets+1] = i*8+j
	    nnets = nnets + 1
	 end
      end
   end
   return nnets,nets
end

function chudp.dissector(tvbuf, pinfo, tree)
   pinfo.cols.protocol:set("CHUDP")
   local plen = tvbuf:reported_length_remaining()
   local subtree = tree:add(chudp, tvbuf:range(0, plen), "Chaos-over-UDP")
   -- Chaosnet UDP Header.
   local chudp_tree = subtree:add(tvbuf(0, 4), "CHUDP header")
   chudp_tree:add(tvbuf(0, 1), "Version: " .. tvbuf(0, 1)) -- version 1 is defined
   chudp_tree:add(tvbuf(1, 1), "Function: " .. tvbuf(1, 1)) -- 1 means PKT
   chudp_tree:add(tvbuf(2, 1), "Argument 1: " .. tvbuf(2, 1)) -- mbz for version 1
   chudp_tree:add(tvbuf(3, 1), "Argument 2: " .. tvbuf(3, 1)) -- mbz for version 1

   -- Go dissect the chaos packet
   local ch = Dissector.get("chaos")
   local tv = tvbuf(4, plen - 4):tvb()
   ch:call(tv, pinfo, tree)
end

function chaos.dissector(tvb, pinfo, tree)
   local bendian = false
   -- It would be nice to just call this with fourth arg true if Chaos-over-UDP case (big-endian),
   -- but adding an argument doesn't seem to work, so here is a horrible workaround.
   -- port_type seems to be 0 for Chaos-over-Ether and Chaos-over-IP, but 3 for Chaos-over-UDP.
   if pinfo['port_type'] == 3 then -- @@@@ aargh
      bendian = true
   end
   -- Shows protocol fields correctly, but for strings only suffixes [BE] to indicated they are swapped.

   pinfo.cols.protocol:set("Chaos"..(bendian and " (BE)" or "")) -- keep it terse

   local pktlen = tvb:reported_length_remaining()
   local pktlen_remaining = pktlen
   
   local subtree = tree:add(chaos, tvb:range(0, pktlen), "Chaosnet (length "..pktlen..(bendian and ", BE" or "")..")")

   if pktlen < CHAOS_HDR_LEN then
      tree:add_proto_expert_info(ef_too_short)
      return
   end

   -- Chaosnet header.
   local chaos_tree = subtree:add(tvb(0, CHAOS_HDR_LEN), "Header")
   -- Note: MSB is opcode, but 16b-word is swapped
   local opcode = bendian and tvb(0,1):uint() or tvb(1,1):uint()
   local opdesc = ""
   if opcode > 0 and opcode <= #opc_names then
      opdesc = " (" .. opc_names[opcode] .. ")"
   elseif opcode >= 128 and opcode < 192 then -- #o200 and #o300 respectively
      opdesc = " (DAT)"
   elseif opcode >= 192 then
      opdesc = " (DAT2)"
   end
   chaos_tree:add(tvb(0, 2), "Operation: " .. string.format("%#o",opcode) .. opdesc)
      
   --- 4 bit forwarding count, 12 bit data count
   -- note swappedness
   local d = bendian and tvb:range(2,2):int() or tvb:range(2,2):le_int()
   local forward_count = bit.rshift(d,12)
   local data_count = bit.band(d, 0xfff)
   local src = bendian and string.format("%#o",tvb(8, 2):uint()) or string.format("%#o",tvb(8, 2):le_uint())
   local srcidx = bendian and tvb(10, 2):uint() or tvb(10, 2):le_uint()
   local dest = bendian and string.format("%#o",tvb(4, 2):uint()) or string.format("%#o",tvb(4, 2):le_uint())
   local destidx = bendian and tvb(6, 2):uint() or tvb(6, 2):le_uint()
   local pktno = bendian and tvb(12, 2):uint() or tvb(12, 2):le_uint()
   local ackno = bendian and tvb(14, 2):uint() or tvb(14, 2):le_uint()
   -- add the brief info
   pinfo.cols.info:set("<"..src..","..srcidx.."> => <"..dest..","..destidx..">"..opdesc)
   chaos_tree:add(tvb(2, 2), "Fwd count: " .. forward_count .. ", Data length: " .. data_count)
   chaos_tree:add(tvb(4, 4), "Dest address " .. dest .. ", index " .. destidx)
   chaos_tree:add(tvb(8, 4), "Source address " .. src .. ", index " .. srcidx)
   chaos_tree:add(tvb(12, 4), "Packet nr: " .. pktno .. ", Ack nr: " .. ackno)

   -- Data.
   if opcode == 8 then		-- RUT, complex content
      local data_tree = subtree:add(tvb(CHAOS_HDR_LEN, data_count), "RUT data (routing table)")
      for i=0,data_count-4,4 do
	 local netnum = bendian and tvb(CHAOS_HDR_LEN+i,2):uint() or tvb(CHAOS_HDR_LEN+i,2):le_uint()
	 local cost = bendian and tvb(CHAOS_HDR_LEN+i+2,2):uint() or tvb(CHAOS_HDR_LEN+i+2,2):le_uint()
	 data_tree:add(tvb(CHAOS_HDR_LEN+i,4), "Net "..string.format("%#o",netnum).." cost "..cost)
      end
   else
      local repr
      local truncated = data_count > 64 and "..." or ""
      if opcode == 1 or opcode == 3 or opcode == 9 then		-- RFC or CLS or LOS
	 local s = tvb(CHAOS_HDR_LEN, math.min(data_count, 64)):string()..truncated..(bendian and " [BE]" or "")
	 repr = "String ("..data_count.."): " .. s
	 pinfo.cols.info:append(" "..s)
      elseif opcode == 14 then	-- BRD
	 -- Ack field says how long the subnet bitmap is
	 local ackn = bendian and tvb(14,2):uint() or tvb(14,2):le_uint()
	 local subs = tvb(CHAOS_HDR_LEN, ackn) -- subnet mask is here
	 local nn,n = parse_subnet_mask(subs,ackn) -- parse it, get number of nets and a list of them
	 -- contact name
	 local contact = tvb(CHAOS_HDR_LEN+ackn,data_count-ackn):string()..(bendian and " [BE]" or "")
	 local ns
	 if nn > 5 then
	    ns = n[1].." to "..((#n)-1) -- if many, only give range (zero-based)
	 else
	    ns = table.concat(n,",") -- else give the full list
	 end
	 repr = "Broadcast to "..nn.." subnet"..(nn == 1 and "" or "s").." ("..ns.."), contact: "..contact
	 pinfo.cols.info:append(" "..contact)
      else
	 -- Show it as a string if it is DAT
	 if opcode >= 128 and opcode < 192 then
	    repr = "Data ("..data_count.."): " .. tvb(CHAOS_HDR_LEN, math.min(data_count, 64)):string()..truncated
	 else
	    repr = "Data ("..data_count.."): " .. tvb(CHAOS_HDR_LEN, math.min(data_count, 64))..truncated
	 end
      end
      local data_tree = subtree:add(tvb(CHAOS_HDR_LEN, data_count), repr)
   end

   -- End. Return the number of bytes we consumed
   return CHAOS_HDR_LEN + data_count
end

-- Add it for Chaos-over-IP
DissectorTable.get("ip.proto"):add(16, chaos)
-- and add it for Ethernet
DissectorTable.get("ethertype"):add(0x0804, chaos)
-- and to UDP table
udp_table = DissectorTable.get("udp.port")
udp_table:add(42042, chudp)
udp_table:add(42043, chudp)
