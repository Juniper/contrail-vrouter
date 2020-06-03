package.prepend_path("/Applications/Wireshark.app/Contents/PlugIns/wireshark/wireshark_plugin")
require("common");

-- returns whether to hide a branch or not
function to_hide(data_len, value, show_field_when_zero)
  -- when data_len is 0 then value turns out to be nil
  if data_len == 0 then
    hide = true
    value = nil
  end
  -- zero values will not be shown
  if tonumber(tostring(value),16) == 0 then
    hide = true
  end
  -- selectively showing branch
  if data_len ~= 0 and show_field_when_zero then
    hide = false
  end
  return hide, value
end

-- checks if ntoh needed or not
function ntoh(ttype)
  if ttype == "T_U8" or ttype == "T_U16" or ttype == "T_U32" or
                                               ttype == "T_U64" then
    return true
  else
    return false
  end
end

-- returns table length
function tablelength(T)
  local count = 0
  for _ in pairs(T) do count = count + 1 end
  return count
end

-- converts array to string
function convert_arr_to_str(arr, sep, host_endianness)
  str = ""
  if host_endianness then
    if get_host_endianness() == ENC_LITTLE_ENDIAN then
      for i = tablelength(arr), 1, -1 do
        if i == 1 then
          str = str ..  tostring(arr[i])
        else
          str = str ..  tostring(arr[i]) .. sep
        end
      end
    end
  end

  if not(host_endianness) or get_host_endianness() == ENC_BIG_ENDIAN then
    for i = 1, tablelength(arr) do
      if i == tablelength(arr) then
        str = str ..  tostring(arr[i])
      else
        str = str ..  tostring(arr[i]) .. sep
      end
    end
  end
  return str
end

-- to calculate endianness of the host
function get_host_endianness()
  endianness = string.dump(function() end):byte(7)
  if endianness == 1 then
    sys_endian = ENC_LITTLE_ENDIAN
  else
    sys_endian = ENC_BIG_ENDIAN
  end
  return sys_endian
end

-- adds ttype and sr number to the branch
function add_ttype_and_sr_number(branch, field_name, ttype, serial_number)
  f = sandesh_proto.fields
  branch:add(f[field_name .. "_ttype"], ttype):append_text(
                                          " (" .. TType[ttype:uint()] .. ")")
  branch:add(f[field_name .. "_sr_no"], serial_number)
end

-- converts binary to hex
function tohex(num)
  local charset = {"0","1","2","3","4","5","6","7","8","9",
                                       "a","b","c","d","e","f"}
  local tmp = {}
  repeat
    table.insert(tmp,1,charset[num%16+1])
    num = math.floor(num/16)
  until num==0
  return table.concat(tmp)
end

-- converts decimal to binary
function byte2bin(n)
  local t = {}
  for i=3,0,-1 do
    t[#t+1] = math.floor(n / 2^i)
    n = n % 2^i
  end
  return table.concat(t)
end

-- returns an array of decoded_bits
function get_decoded_bits(msg, datasize)
  bin_msg = ""
  for i = 1, string.len(msg)  do
    local c = msg:sub(i,i)
    bin = byte2bin(tonumber(c, 16))
    bin_msg = bin_msg .. bin
  end

  arr = {}
  for i = string.len(bin_msg), 1, -1 do
    local c = string.sub(bin_msg,i,i)
    if c == '1' then
      front = string.rep('0', i-1)
      back = string.rep('0', datasize-i)
      value = front .. c .. back
      table.insert(arr, value)
    end
  end

  decoded_bits = {}
  for i = 1 , #arr do
    hex_decoded_bits = ""
    j=1
    while(j<=datasize) do
      local c = string.sub(arr[i],j,j+3)
      dec = tonumber(c, 2)
      hex_decoded_bits = hex_decoded_bits .. tohex(dec)
      j = j + 4
    end
    table.insert(decoded_bits, hex_decoded_bits)
  end

  return decoded_bits
end

-- adds respective decoded_bits to the decoded_bits_branch
function add_decoded_bits_to_branch(field_name, decoded_bits_lookup_table,
                                     branch, decoded_bits_branch, value,
                                     offset, datatype_size, field_val_info_col)
  local f = sandesh_proto.fields
  decoded_bits = get_decoded_bits(tostring(value), datatype_size*8)
  if #decoded_bits ~= 0 then
    branch:append_text(": ")
  end
  local str = ""
  for i = 1, #decoded_bits do
    local decoded_bits_buffer = ByteArray.new(string.rep('0', offset*2) ..
                                        decoded_bits[i]):tvb(
                                        decoded_bits_lookup_table[
                                        "0x" .. decoded_bits[i]])
    decoded_bits_branch:add(f[decoded_bits_lookup_table[
                                        "0x" .. decoded_bits[i]]],
                                        decoded_bits_buffer(
                                        decoded_bits_buffer:len()-datatype_size,
                                        datatype_size))
    decoded_bits_str = decoded_bits_lookup_table["0x" .. decoded_bits[i]]
    if i ~= 1 then
      str =  str .. ", " .. decoded_bits_str
      branch:append_text(", " .. decoded_bits_str)
    else
      str = str .. decoded_bits_str
      branch:append_text(decoded_bits_str)
    end
    added_to_branch = true
  end

  if field_val_info_col then
    info_col[field_name] = {prepend = field_val_info_col.prepend, value = str}
  end
  return str
end

-- converts given list to its list_datatype
function convert_to_list_datatype(value, list_size_in_dec,
                                      element_type_size, ttype)
  arr = {}
  if value ~= 0  then
    local i = 0
    local data_len = list_size_in_dec * element_type_size
    while i ~= data_len  do
      if ttype == "T_BYTE" then
        arr_element = tostring(value(i, element_type_size))
      elseif ttype == "T_I64" or ttype == "T_U64" then
        arr_element = value(i, element_type_size):uint64()
      else
        arr_element = value(i, element_type_size):uint()
      end
      table.insert(arr, arr_element)
      i = i + element_type_size
    end
  end
  return arr
end

-- adds lists to the branch
function add_list(branch, value, list_size_in_dec, element_in_dec,
                               field_name, hide, set_to_default, protofield)
  local str = ""
  if value ~= 0 then
    f = sandesh_proto.fields
    element_type_size = datatype_size[TType[element_in_dec]]
    arr = convert_to_list_datatype(value, list_size_in_dec,
                                    element_type_size, TType[element_in_dec])
    if ntoh(TType[element_in_dec]) then
      str = convert_arr_to_str(arr, " ", true)
    else
      str = convert_arr_to_str(arr, " ", false)
    end
    val_branch = branch:add(f[field_name .. "_value"], value)

    if set_to_default and tostring(value) == set_to_default.buffer then
      branch:append_text(": " .. set_to_default.display)
      val_branch:append_text(" (" .. set_to_default.display .. ")")
    else
      if element_type_size ~= 1 then
        val_branch:append_text(" ([" .. str .. "])")
      end
      if (TType[element_in_dec] == "T_BYTE" and
                string.match(field_name, "name")) or
                protofield == ProtoField.string or
                protofield == ProtoField.stringz then
        table_str = {}
        for i = 0, list_size_in_dec-1
        do
          if tostring(value(i,1)) == "00"  then
            table.insert(table_str," ")
          else
            table.insert(table_str, string.char(tonumber(
                                                   tostring(value(i,1)),16)))
          end
        end
        str = convert_arr_to_str(table_str, "", false)
        val_branch:append_text(" (".. str .. ")")
        branch:append_text(": " .. str)
      elseif TType[element_in_dec] == "T_BYTE" and string.match(
                                                       field_name, "mac") then
        str = convert_arr_to_str(arr, ":", false)
        branch:append_text(": " .. str)
      else
        branch:append_text(": " .. "[" .. str .. "]")
      end
    end

    added_to_branch = true
    if field_val_info_col then
      info_col[field_name] = {prepend = field_val_info_col[prepend],
                                                               value = str}
    end
  end
  return str
end

-- returns latest added field value to a field
function get_field_value(field)
  local tbl = { field() }
  return tbl[#tbl]
end

-- appends value wherever needed
function append_value(field_name, field_append_value , use_str,
                           subtree, branch, value_field, value,
                           hide, field_val_info_col, set_to_default)
  if field_append_value and not(hide) then
    for k, v in pairs(field_append_value) do
      if use_str == nil or use_str == "" then
        val_str = get_field_value(field_extractors[field_name .. '_value_str'])
      else
        val_str = use_str
      end
      if k == "branch" and not(added_to_branch) then
        if set_to_default and tostring(value) == set_to_default.buffer then
          branch:append_text(": " .. set_to_default.display)
          value_field:append_text(" (" .. set_to_default.display .. ")")
        else
          branch:append_text(v.prepend .. v.value(tostring(val_str)))
        end
        added_to_branch = true
        if field_val_info_col then
          info_col[field_name] = {prepend = field_val_info_col.prepend,
                                         value = v.value(tostring(val_str))}
        end
      end
      if k == "subtree" then
        subtree:append_text(v.prepend .. v.value(tostring(val_str)))
      end
    end
  end

  if not(added_to_branch) then
    if ipv6_str then
      val_str = ipv6_str
    else
      val_str = get_field_value(field_extractors[field_name .. '_value_str'])
    end
    if set_to_default and tostring(value) == set_to_default.buffer then
      branch:append_text(": " .. set_to_default.display)
      value_field:append_text(" (" .. set_to_default.display .. ")")
    else
      branch:append_text(": " .. tostring(val_str))
    end
    added_to_branch = true
    if field_val_info_col then
      info_col[field_name] = {prepend = field_val_info_col.prepend,
                                                value = tostring(val_str)}
    end
  end
end

-- convert to ipv6 format
function convert_to_ipv6_format(value)
  str = ""
  arr = {}
  i = 0
  while i < string.len(tostring(value))/2 do
    str = str .. tostring(value(i, 2))
    i = i + 2
    table.insert(arr, str)
    str = ""
  end
  str = convert_arr_to_str(arr, ":", true)
  return str
end

-- adds values as per dependency on other field
function add_value_as_per_field(field_name, depends_on_field, branch,
                                     value_field, value, field_val_info_col)
  if string.match(depends_on_field, "family") then
    val_str = get_field_value(field_extractors[depends_on_field  ..
                                                            '_value_str'])
    local str = ""
    if tostring(val_str) == "1" or tostring(val_str) == "2" or
                                             tostring(val_str) == "7" then
      -- ipv4
      if string.match(field_name, "l") then
        if get_host_endianness() == ENC_LITTLE_ENDIAN then
          str = tostring(value(0,-1):le_ipv4())
          branch:append_text(": " .. str)
        else
          str = tostring(value(0,-1):ipv4())
          branch:append_text(": " .. str)
        end
        added_to_branch = true
      end
    else
      -- ipv6
      str = convert_to_ipv6_format(value)
      branch:append_text(": " .. str)
      value_field:append_text(" (" .. str .. ")")
      added_to_branch = true
    end
  end

  if field_val_info_col then
    info_col[field_name] = {prepend = field_val_info_col.prepend, value = str}
  end
  return str
end

-- updates info column
function update_proto_info_col(pinfo, structure, structure_in_info_col,
                                                              protocol_name)
  local pkt_info = pinfo.cols.info
  str = ""
  for k, v in pairs(info_col) do
    if v.value == "nil" or v.value == nil or
                 (string.match(tostring(pkt_info), "Response") and
                 string.match(v.prepend, "Operation: ")) then
      --do nothing
    else
      str = str .. v.prepend .. v.value .. " "
    end
  end
  structure_in_info_col[structure] = true
  if string.match(tostring(pkt_info), "Multiple Sandesh Objects") then
  elseif  string.match(tostring(pkt_info), "Operation") or
                         string.match(tostring(pkt_info), "ID") or
                         string.match(tostring(pkt_info), "Vrf") then
    if not(string.match(tostring(pkt_info), str)) then
      if not(string.match(tostring(pkt_info), structure)) then
        if string.match(tostring(pkt_info), "Response:") and
                          (string.match(tostring(pkt_info), "Multiple") or
                          not(string.match(tostring(pinfo.cols.protocol),
                                                         protocol_name)))then
          sub_str = string.sub(tostring(pkt_info), 1, 20)
          pinfo.cols.info = sub_str .. ", Multiple Sandesh objects"
        elseif string.match(tostring(pkt_info), "Response:")  then
          sub_str = string.sub(tostring(pkt_info), 1, 20)
          pinfo.cols.info = sub_str .. ", Multiple " .. " " .. structure
        elseif (not(string.match(tostring(pkt_info), "Response:")) and
                     string.match(tostring(pkt_info), "Multiple")) or
                     tablelength(structure_in_info_col)>1 then
          pinfo.cols.info = "Multiple Sandesh Objects"
        else
          pinfo.cols.info = "Multiple" .. " " .. structure
        end
      else
        if string.match(tostring(pkt_info), "Response:") then
          sub_str = string.sub(tostring(pkt_info), 1, 20)
          pinfo.cols.info = sub_str .. ", Multiple " .. " " .. structure
        else
          pinfo.cols.info = "Multiple" .. " " .. structure
        end
      end
    end
  else
    if not(string.match(tostring(pkt_info), structure)) then
      if tostring(pkt_info) == "" or string.match(tostring(pkt_info),
                                                           "Response:") then
        pinfo.cols.info = tostring(pkt_info) .. " " .. str
      else
        pinfo.cols.info = "Multiple Sandesh Objects"
      end
    end
  end

  if not(string.match(tostring(pinfo.cols.protocol), protocol_name)) then
    if tostring(pinfo.cols.protocol) == "" then
      pinfo.cols.protocol = tostring(pinfo.cols.protocol) .. protocol_name
    else
      pinfo.cols.protocol = tostring(pinfo.cols.protocol) .. ", " ..
                                                                protocol_name
    end
  end
end

