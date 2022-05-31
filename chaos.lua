-- Chaosnet dissector for Wireshark, based on AMS hack for Chaos-over-UDP
-- Install in ~/.wireshark/plugins, but you might still need to use the -X option (see below).

-- To show Chaosnet packets on Ethernet
-- sudo tshark -X lua_script:/home/pi/.wireshark/plugins/chaos.lua -O chaos ether proto 0x804
-- To skip all RUT packets (assuming ether header length 14):
-- sudo tshark -X lua_script:/home/pi/.wireshark/plugins/chaos.lua -O chaos ether proto 0x804 and 'ether[15] != 8'

-- To show only Chaos-over-IP packets (IP protocol 16):
-- sudo tshark -X lua_script:/home/pi/.wireshark/plugins/chaos.lua -O chaos ip proto 16
-- To show only a specific host, and skip all RUT packets (assuming IP header length 20):
-- sudo tshark -X lua_script:/home/pi/.wireshark/plugins/chaos.lua -O chaos ip proto 16 and ip host 10.0.1.73 and 'ip[21] != 8'

-- For the Wireshark lua stuff, see https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html

chaos = Proto("chaos", "Chaosnet")

local CHAOS_HDR_LEN = 16

local ef_too_short = ProtoExpert.new("chaos.too_short.expert", "Packet too short", expert.group.MALFORMED, expert.severity.ERROR)
chaos.experts = { ef_too_short }

-- Chaos opcode names
local opc_names = { "RFC", "OPN", "CLS", "FWD", "ANS", "SNS", "STS",
       "RUT", "LOS", "LSN", "MNT", "EOF", "UNC", "BRD" }

function chaos.dissector(tvb, pinfo, tree)
   -- print("CHAOS dissector starting")
   pinfo.cols.protocol = "CHAOS"

   local pktlen = tvb:reported_length_remaining()
   local pktlen_remaining = pktlen
   
   local subtree = tree:add(chaos, tvb:range(0, pktlen), "Chaosnet (length "..pktlen..")")

   if pktlen < CHAOS_HDR_LEN then
      tree:add_proto_expert_info(ef_too_short)
      return
   end

   -- Chaosnet header.
   local chaos_tree = subtree:add(tvb(0, CHAOS_HDR_LEN), "Header")
   -- Note: MSB is opcode, but 16b-word is swapped
   local opcode = tvb(1, 1):uint()
   chaos_tree:add(tvb(0, 2), "Operation: " .. string.format("%#o",opcode) .. " (" .. opc_names[opcode] .. ")")
   --- 4 bit forwarding count, 12 bit data count
   -- note swappedness
   local d = tvb:range(2, 2):le_int()
   local forward_count = bit.rshift(d,12)
   local data_count = bit.band(d, 0xfff)
   chaos_tree:add(tvb(2, 2), "FC: " .. forward_count .. ", Len: " .. data_count)
   chaos_tree:add(tvb(4, 4), "Dest address " .. string.format("%#o",tvb(4, 2):le_uint()) ..
                             ", index " .. tvb(6, 2):le_uint())
   chaos_tree:add(tvb(8, 4), "Source address " .. string.format("%#o",tvb(8, 2):le_uint()) ..
		             ", index " .. tvb(10, 2):le_uint())
   chaos_tree:add(tvb(12, 4), "Packet nr: " .. tvb(12, 2):le_uint() ..
		              ", Ack nr: " .. tvb(14, 2):le_uint())

   -- Data.
   local repr
   if opcode == 1 or opcode == 3 or opcode == 9 then		-- RFC or CLS or LOS
      repr = "String ("..data_count.."): " .. tvb(CHAOS_HDR_LEN, math.min(data_count, 64)):string()
   else
      repr = "Data ("..data_count.."): " .. tvb(CHAOS_HDR_LEN, math.min(data_count, 64))
   end
   local data_tree = subtree:add(tvb(CHAOS_HDR_LEN, data_count), repr)

   -- Fin.
   pktlen_remaining = pktlen_remaining - CHAOS_HDR_LEN - data_count
   -- print("CHAOS dissector finished: remaining", pktlen_remaining)
   return pktlen_remaining
end

-- Add it for Chaos-over-IP
ip_table = DissectorTable.get("ip.proto")
ip_table:add(16, chaos)
-- and add it for Ethernet
ether_table = DissectorTable.get("ethertype")
ether_table:add(0x0804, chaos)
