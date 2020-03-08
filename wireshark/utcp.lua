-- UTCP dissector

utcp_protocol = Proto("UTCP", "User-space Transport Control Protocol")
utcp_protocol.fields = {}

src = ProtoField.uint16("utcp.src", "src", base.DEC)
dst = ProtoField.uint16("utcp.dst", "dst", base.DEC)
seq = ProtoField.uint32("utcp.seq", "seq", base.DEC)
ack = ProtoField.uint32("utcp.ack", "ack", base.DEC)
wnd = ProtoField.uint32("utcp.wnd", "wnd", base.DEC)
ctl = ProtoField.uint16("utcp.ctl", "ctl", base.HEX)
aux = ProtoField.uint16("utcp.aux", "aux", base.HEX)
aux_init = ProtoField.uint32("utcp.aux_init", "aux_init", base.HEX)

utcp_protocol.fields = {src, dst, seq, ack, wnd, ctl, aux, aux_init}

ctltext = {"SYN", "ACK", "SYN ACK", "FIN", "SYN FIN", "ACK FIN", "SYN ACK FIN", "RST", "SYN RST", "ACK RST", "SYN ACK RST", "FIN RST", "SYN FIN RST", "ACK FIN RST", "SYN ACK FIN RST"}

function ctl_to_text(ctl)
  text = ctltext[ctl]
  if text == nil then return "" end
  return " (" .. text .. ")"
end

function utcp_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = utcp_protocol.name

  local subtree = tree:add(utcp_protocol, buffer(), "UTCP Protocol Data")
  local ctl_text = ctl_to_text(buffer(16, 2):le_int())
  local aux_field = buffer(18, 2):le_int()
  local aux_len = 4 * ((aux_field - aux_field % 256) / 256) % 16
  local aux_type = aux_field % 256
  local aux_text = ""
  if aux_field ~= 0 then
      aux_text = " (type " .. aux_type .. " length " .. aux_len .. ")"
  end

  subtree:add_le(src, buffer(0, 2))
  subtree:add_le(dst, buffer(2, 2))
  subtree:add_le(seq, buffer(4, 4))
  subtree:add_le(ack, buffer(8, 4))
  subtree:add_le(wnd, buffer(12, 4))
  subtree:add_le(ctl, buffer(16, 2)):append_text(ctl_text)
  subtree:add_le(aux, buffer(18, 2)):append_text(aux_text)

  if aux_field == 257 then
      local flags = buffer(23, 1):le_int()
      local flags_text = ""
      if flags == 0 then flags_text = " (UDP)"
      elseif flags == 3 then flags_text = " (TCP)"
      end
      subtree:add_le(aux_init, buffer(20, 4)):append_text(flags_text)
  end
end

-- Assume we run the test program on port 9999

local udp_port = DissectorTable.get("udp.port")
udp_port:add(9999, utcp_protocol)
