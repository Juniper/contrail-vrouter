package.prepend_path("/Applications/Wireshark.app/Contents/PlugIns/wireshark/wireshark_plugin")
require("helpers");
require("common");

sandesh_dt = DissectorTable.new("sandesh_table")

sandesh_proto = Proto("sandesh", "Sandesh Protocol")
sandesh_proto.fields = {}
field_extractors = {}
for i = 1, tablelength(sandesh_global)
do
  sandesh_proto.fields[sandesh_global[i].name] = ProtoField.protocol(
                                                   sandesh_global[i].abv,
                                                   sandesh_global[i].name)
  object_table = sandesh_global[i].table
  for k, v in pairs(object_table)
  do

    sandesh_proto.fields[v.field_name] = ProtoField.none(
                             sandesh_global[i].abv .. '.' .. v.field_name,
                             v.field_name)
    sandesh_proto.fields[v.field_name .. '_ttype'] = ProtoField.bytes(
                    sandesh_global[i].abv .. '.' .. v.field_name .. '.ttype',
                    "TType")
    sandesh_proto.fields[v.field_name .. '_sr_no'] = ProtoField.uint16(
                  sandesh_global[i].abv .. '.' .. v.field_name .. '.sr_no',
                  "Serial Number",
                   base.DEC)
    sandesh_proto.fields[v.field_name .. "_list_datatype"] = ProtoField.bytes(
             sandesh_global[i].abv .. '.' .. v.field_name .. '.list_datatype',
             "List Datatype")
    sandesh_proto.fields[v.field_name .. "_list_length"] = ProtoField.uint32(
               sandesh_global[i].abv .. '.' .. v.field_name .. '.list_length',
               "List Length",
               base.DEC)
    sandesh_proto.fields[v.field_name .. '_value'] = v.ProtoField(
                sandesh_global[i].abv .. '.' .. v.field_name .. '.value',
                "Value",
                v.base)
    field_extractors[v.field_name .. '_value_str'] = Field.new(
                sandesh_global[i].abv .. '.' .. v.field_name .. '.value')
  end

  if sandesh_global[i].decode_bits then
    for j = 1, tablelength(sandesh_global[i].decode_bits) do
      for key, val in pairs(sandesh_global[i].decode_bits[j][1]) do
        sandesh_proto.fields[val] = sandesh_global[i].decode_bits[j][2](
                                          val,
                                          val,
                                          base.HEX,
                                          nil,
                                          sandesh_global[i].decode_bits[j][3])
      end
    end
  end
end

function sandesh_proto.init()
  DissectorTable.get("sandesh_table"):add(147, sandesh_proto)
end

-- dissects the buffer
function object_dissector(structure, buffer, pinfo, tree, structure_table,
                                 length, structure_in_info_col, protocol_name)
  local offset = 0
  local f = sandesh_proto.fields
  local subtree = tree:add(f[structure], buffer(offset, -1))
  offset = offset + length + 1
  info_col = {}
  while(TType[buffer(offset,1):uint()] ~= "T_STOP")
    do
      local ttype = buffer(offset, 1)
      local data_len = datatype_size[TType[ttype:uint()]]
      offset = offset + 1
      local serial_number = buffer(offset,2)
      local field_name = structure_table[serial_number:uint()].field_name
      local field_datatype = structure_table[serial_number:uint()].datatype
      local field_append_value =  structure_table[serial_number:uint()].append_value
      local field_val_info_col = structure_table[serial_number:uint()].info_col
      local show_field_when_zero = structure_table[serial_number:uint()].show_when_zero
      local set_to_default = structure_table[serial_number:uint()].default
      local decode_bits_table = structure_table[serial_number:uint()].decode_bits
      local depends_on_field = structure_table[serial_number:uint()].depends_on
      local protofield = structure_table[serial_number:uint()].ProtoField
      local is_resp_greater = true
      local use_str = ""
      added_to_branch = false
      offset = offset + 2
      -- to check if datatype is of variable len
      if data_len == "variable" then
        if TType[ttype:uint()] == "T_LIST" then
          element = buffer(offset,1)
          element_in_dec = element:uint()
          element_type_size = datatype_size[TType[element_in_dec]]
          offset = offset + 1
        end
        if TType[ttype:uint()] == "T_STRING" then
          element_in_dec = 3
          element_type_size = datatype_size[TType[element_in_dec]]
        end
        list_size_in_hex = buffer(offset , 4)
        data_len = list_size_in_hex:uint() * element_type_size
        offset = offset + 4
      end
      local value  = buffer(offset, data_len)
      hide  = false
      hide , value =  to_hide(data_len, value, show_field_when_zero)
      branch  = subtree:add(f[field_name])
      add_ttype_and_sr_number(branch, field_name, ttype, serial_number)

      if  datatype_size[TType[ttype:uint()]] == "variable" then
        if TType[ttype:uint()] == "T_LIST" then
          branch:add(f[field_name .. "_list_datatype"], element):append_text(
                                         " (" .. TType[element_in_dec] .. ")")
        end
        branch:add(f[field_name .. "_list_length"], list_size_in_hex)

      end
      if value == nil then
        -- do nothing
      elseif depends_on_field then
        value_field = branch:add(f[field_name .. "_value"], value)
        use_str = add_value_as_per_field(field_name, depends_on_field,
                                                 branch, value_field, value)
        --elseif decode_bits is present then
      elseif decode_bits_table then
        decoded_bits_branch = branch:add(f[field_name .. "_value"], value)
        use_str = add_decoded_bits_to_branch(field_name, decode_bits_table,
                                               branch, decoded_bits_branch,
                                               value, offset, data_len,
                                               field_val_info_col)

        -- to convert to ntoh
      elseif ntoh(TType[ttype:uint()]) then
        if field_name == "resp_code" and value:uint() == 0 then
          is_resp_greater = false
        end
        value_field = branch:add_packet_field(f[field_name .. "_value"],
                                                 value, get_host_endianness())
      elseif  TType[ttype:uint()] == "T_LIST" then
        use_str = add_list(branch, value, list_size_in_hex:uint(),
                             element_in_dec, field_name, hide,
                             set_to_default, protofield)
      else
        value_field = branch:add(f[field_name .. "_value"], value)
        if string.match(field_name, "ip6_u") or
                string.match(field_name, "ip6_l") then
          use_str = covert_to_ipv6_format(value)
          value_field:append_text(" (" .. ipv6_str .. ")")
        end
      end
      append_value(field_name, field_append_value, use_str, subtree,
                       branch, value_field, value, hide, field_val_info_col,
                       set_to_default)
      branch:set_hidden(hide)
      offset = offset + data_len

    end
    update_proto_info_col(pinfo, structure, structure_in_info_col, protocol_name)
    tree:add(buffer(offset, 1), "T_STOP"):set_hidden()
    if structure == "vr_response" and is_resp_greater then
      return offset + 27
    else
      return offset
    end
end

-- returns structure name
local function structure_name(buffer, tree, length_parsed, actual_buffer_len)
  local struct_offset = 0
  local struct_str = ""
  local length  = tonumber(tostring(buffer(struct_offset,1)), 16)

  if length+1 < buffer:len() then
    local structure = {}
    tree:add(buffer(struct_offset, 1), "Structure Name Length"):set_hidden()
    struct_offset = struct_offset + 1
    for i = struct_offset, struct_offset+length-1
    do
      table.insert(structure, string.char(tonumber(tostring(buffer(i,1)),16)))
    end
    struct_str = table.concat(structure)
    tree:add(buffer(struct_offset, length), "Structure Name"):set_hidden()
  else
    length = 0
  end
  return struct_str , length
end

-- updates src, dst
local function update_src_dst_cols(pinfo)
  if pinfo.p2p_dir  == 1 then
    pinfo.cols.src = "Vrouter"
    pinfo.cols.dst = "Agent"
  else
    pinfo.cols.src = "Agent"
    pinfo.cols.dst = "Vrouter"
  end
end

function sandesh_proto.dissector(buffer, pinfo, tree)
  update_src_dst_cols(pinfo)
  offset =  27
  structure_in_info_col = {}
  length_parsed = 0
  while(offset<buffer:len()) do
    local struct_str , length = structure_name(buffer(offset, -1),
                                               tree,
                                               length_parsed,
                                               buffer:len())
    offset = offset + 1

    for i = 1, tablelength(sandesh_global)
    do
      if struct_str == sandesh_global[i].name then
        structure_table = sandesh_global[i].table
        length_parsed = object_dissector(struct_str,
                                         buffer(offset-1, -1),
                                         pinfo,
                                         tree,
                                         structure_table,
                                         length,
                                         structure_in_info_col,
                                         sandesh_global[i].protocol)
        offset = offset + length_parsed
      end
    end
  end
end




