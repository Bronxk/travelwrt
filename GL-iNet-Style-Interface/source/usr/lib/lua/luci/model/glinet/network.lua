-- GL.iNet Style Interface Network Model
-- network.lua - Network management functions

local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()
local nixio = require "nixio"
local json = require "luci.jsonc"
local ubus = require "ubus"

local M = {}

-- Helper function to execute commands safely
local function exec_command(cmd)
    local handle = io.popen(cmd .. " 2>&1")
    if handle then
        local result = handle:read("*a")
        handle:close()
        return result
    end
    return nil
end

-- Get network interfaces
function M.get_interfaces()
    local interfaces = {}
    local conn = ubus.connect()
    
    if conn then
        local status = conn:call("network.interface", "dump", {})
        conn:close()
        
        if status and status.interface then
            for _, iface in ipairs(status.interface) do
                table.insert(interfaces, {
                    name = iface.interface,
                    proto = iface.proto,
                    up = iface.up,
                    device = iface.device,
                    ipv4_addr = iface["ipv4-address"] and iface["ipv4-address"][1] or nil,
                    ipv6_addr = iface["ipv6-address"] and iface["ipv6-address"][1] or nil,
                    uptime = iface.uptime,
                    data = iface.data
                })
            end
        end
    end
    
    return interfaces
end

-- Get WAN status
function M.get_wan_status()
    local wan_iface = uci:get("network", "wan", "ifname") or "eth0"
    local conn = ubus.connect()
    local status = {
        connected = false,
        proto = uci:get("network", "wan", "proto") or "dhcp",
        ip = nil,
        gateway = nil,
        dns = {},
        uptime = 0
    }
    
    if conn then
        local wan_status = conn:call("network.interface.wan", "status", {})
        conn:close()
        
        if wan_status then
            status.connected = wan_status.up or false
            status.uptime = wan_status.uptime or 0
            
            if wan_status["ipv4-address"] and wan_status["ipv4-address"][1] then
                status.ip = wan_status["ipv4-address"][1].address
            end
            
            if wan_status.route then
                for _, route in ipairs(wan_status.route) do
                    if route.target == "0.0.0.0" and route.mask == 0 then
                        status.gateway = route.nexthop
                        break
                    end
                end
            end
            
            if wan_status["dns-server"] then
                status.dns = wan_status["dns-server"]
            end
        end
    end
    
    -- Get additional info
    local wan_info = exec_command("ifconfig " .. wan_iface .. " 2>/dev/null")
    if wan_info then
        local rx_bytes = wan_info:match("RX bytes:(%d+)")
        local tx_bytes = wan_info:match("TX bytes:(%d+)")
        status.rx_bytes = tonumber(rx_bytes) or 0
        status.tx_bytes = tonumber(tx_bytes) or 0
    end
    
    return status
end

-- Configure WAN
function M.configure_wan(config)
    if not config.proto then
        return nil, "Protocol not specified"
    end
    
    -- Set protocol
    uci:set("network", "wan", "proto", config.proto)
    
    if config.proto == "dhcp" then
        -- DHCP configuration
        uci:delete("network", "wan", "ipaddr")
        uci:delete("network", "wan", "netmask")
        uci:delete("network", "wan", "gateway")
        uci:delete("network", "wan", "dns")
        
    elseif config.proto == "static" then
        -- Static IP configuration
        if not config.ipaddr or not config.netmask then
            return nil, "IP address and netmask required for static configuration"
        end
        
        uci:set("network", "wan", "ipaddr", config.ipaddr)
        uci:set("network", "wan", "netmask", config.netmask)
        
        if config.gateway then
            uci:set("network", "wan", "gateway", config.gateway)
        end
        
        if config.dns then
            uci:set("network", "wan", "dns", table.concat(config.dns, " "))
        end
        
    elseif config.proto == "pppoe" then
        -- PPPoE configuration
        if not config.username or not config.password then
            return nil, "Username and password required for PPPoE"
        end
        
        uci:set("network", "wan", "username", config.username)
        uci:set("network", "wan", "password", config.password)
    end
    
    -- Commit changes and restart network
    uci:commit("network")
    os.execute("/etc/init.d/network restart")
    
    return true
end

-- Get LAN status
function M.get_lan_status()
    local status = {
        ip = uci:get("network", "lan", "ipaddr") or "192.168.1.1",
        netmask = uci:get("network", "lan", "netmask") or "255.255.255.0",
        dhcp_enabled = uci:get("dhcp", "lan", "ignore") ~= "1",
        dhcp_start = uci:get("dhcp", "lan", "start") or "100",
        dhcp_limit = uci:get("dhcp", "lan", "limit") or "150",
        lease_time = uci:get("dhcp", "lan", "leasetime") or "12h"
    }
    
    return status
end

-- Configure LAN
function M.configure_lan(config)
    if config.ipaddr then
        uci:set("network", "lan", "ipaddr", config.ipaddr)
    end
    
    if config.netmask then
        uci:set("network", "lan", "netmask", config.netmask)
    end
    
    -- DHCP settings
    if config.dhcp_enabled ~= nil then
        uci:set("dhcp", "lan", "ignore", config.dhcp_enabled and "0" or "1")
    end
    
    if config.dhcp_start then
        uci:set("dhcp", "lan", "start", config.dhcp_start)
    end
    
    if config.dhcp_limit then
        uci:set("dhcp", "lan", "limit", config.dhcp_limit)
    end
    
    if config.lease_time then
        uci:set("dhcp", "lan", "leasetime", config.lease_time)
    end
    
    uci:commit("network")
    uci:commit("dhcp")
    
    os.execute("/etc/init.d/network restart")
    os.execute("/etc/init.d/dnsmasq restart")
    
    return true
end

-- Get wireless status
function M.get_wireless_status()
    local status = {
        enabled = false,
        ssid = nil,
        channel = nil,
        mode = nil,
        encryption = nil,
        devices = {}
    }
    
    -- Get wireless configuration
    uci:foreach("wireless", "wifi-device", function(device)
        local dev_info = {
            name = device[".name"],
            disabled = device.disabled == "1",
            channel = device.channel,
            hwmode = device.hwmode,
            networks = {}
        }
        
        -- Get networks for this device
        uci:foreach("wireless", "wifi-iface", function(iface)
            if iface.device == device[".name"] then
                table.insert(dev_info.networks, {
                    ssid = iface.ssid,
                    mode = iface.mode or "ap",
                    encryption = iface.encryption or "none",
                    disabled = iface.disabled == "1",
                    network = iface.network
                })
                
                -- Set main status from first AP network
                if iface.mode == "ap" and not status.ssid then
                    status.enabled = iface.disabled ~= "1"
                    status.ssid = iface.ssid
                    status.encryption = iface.encryption
                end
            end
        end)
        
        table.insert(status.devices, dev_info)
    end)
    
    -- Get connected stations
    local stations = {}
    local iw_output = exec_command("iw dev wlan0 station dump 2>/dev/null")
    if iw_output then
        for mac in iw_output:gmatch("Station (%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)") do
            table.insert(stations, mac)
        end
    end
    status.connected_stations = #stations
    
    return status
end

-- Scan for wireless networks
function M.scan_wireless()
    local networks = {}
    local scan_output = exec_command("iwinfo wlan0 scan 2>/dev/null")
    
    if scan_output then
        local current = {}
        for line in scan_output:gmatch("[^\n]+") do
            local bssid = line:match("Cell %d+ %- Address: (%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
            if bssid then
                if current.bssid then
                    table.insert(networks, current)
                end
                current = { bssid = bssid }
            end
            
            local ssid = line:match('ESSID: "([^"]*)"')
            if ssid then
                current.ssid = ssid
            end
            
            local channel = line:match("Channel: (%d+)")
            if channel then
                current.channel = tonumber(channel)
            end
            
            local signal = line:match("Signal: (%-?%d+)")
            if signal then
                current.signal = tonumber(signal)
            end
            
            local encryption = line:match("Encryption: (.+)")
            if encryption then
                current.encryption = encryption:trim()
            end
        end
        
        if current.bssid then
            table.insert(networks, current)
        end
    end
    
    -- Sort by signal strength
    table.sort(networks, function(a, b)
        return (a.signal or -100) > (b.signal or -100)
    end)
    
    return networks
end

-- Configure wireless
function M.configure_wireless(config)
    if not config.device then
        config.device = "radio0"  -- Default device
    end
    
    -- Find or create wifi-iface section
    local iface_section = nil
    uci:foreach("wireless", "wifi-iface", function(s)
        if s.device == config.device and s.mode == "ap" then
            iface_section = s[".name"]
            return false
        end
    end)
    
    if not iface_section then
        iface_section = uci:add("wireless", "wifi-iface")
        uci:set("wireless", iface_section, "device", config.device)
        uci:set("wireless", iface_section, "mode", "ap")
        uci:set("wireless", iface_section, "network", "lan")
    end
    
    -- Configure settings
    if config.ssid then
        uci:set("wireless", iface_section, "ssid", config.ssid)
    end
    
    if config.encryption then
        uci:set("wireless", iface_section, "encryption", config.encryption)
        
        if config.key and config.encryption ~= "none" then
            uci:set("wireless", iface_section, "key", config.key)
        end
    end
    
    if config.channel then
        uci:set("wireless", config.device, "channel", config.channel)
    end
    
    if config.disabled ~= nil then
        uci:set("wireless", iface_section, "disabled", config.disabled and "1" or "0")
        uci:set("wireless", config.device, "disabled", config.disabled and "1" or "0")
    end
    
    uci:commit("wireless")
    os.execute("wifi reload")
    
    return true
end

-- Get connected clients
function M.get_connected_clients()
    local clients = {}
    local arp_cache = {}
    
    -- Get ARP entries
    local arp_output = exec_command("cat /proc/net/arp")
    if arp_output then
        for line in arp_output:gmatch("[^\n]+") do
            local ip, hw, flags, mac = line:match("(%S+)%s+%S+%s+(%S+)%s+(%S+)%s+%S+%s+(%S+)")
            if ip and mac and mac ~= "00:00:00:00:00:00" and flags == "0x2" then
                arp_cache[mac:upper()] = ip
            end
        end
    end
    
    -- Get DHCP leases
    local lease_file = "/tmp/dhcp.leases"
    local leases = {}
    local f = io.open(lease_file, "r")
    if f then
        for line in f:lines() do
            local expiry, mac, ip, hostname = line:match("(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
            if mac then
                leases[mac:upper()] = {
                    ip = ip,
                    hostname = hostname ~= "*" and hostname or nil,
                    expiry = tonumber(expiry)
                }
            end
        end
        f:close()
    end
    
    -- Get wireless stations
    local wireless_clients = {}
    local iw_output = exec_command("iw dev wlan0 station dump 2>/dev/null")
    if iw_output then
        local current_mac = nil
        for line in iw_output:gmatch("[^\n]+") do
            local mac = line:match("Station (%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
            if mac then
                current_mac = mac:upper()
                wireless_clients[current_mac] = {
                    connected_time = 0,
                    signal = -100,
                    rx_bitrate = 0,
                    tx_bitrate = 0
                }
            elseif current_mac then
                local connected = line:match("connected time:%s+(%d+)")
                if connected then
                    wireless_clients[current_mac].connected_time = tonumber(connected)
                end
                
                local signal = line:match("signal:%s+(%-?%d+)")
                if signal then
                    wireless_clients[current_mac].signal = tonumber(signal)
                end
                
                local rx_bitrate = line:match("rx bitrate:%s+([%d%.]+)")
                if rx_bitrate then
                    wireless_clients[current_mac].rx_bitrate = tonumber(rx_bitrate)
                end
                
                local tx_bitrate = line:match("tx bitrate:%s+([%d%.]+)")
                if tx_bitrate then
                    wireless_clients[current_mac].tx_bitrate = tonumber(tx_bitrate)
                end
            end
        end
    end
    
    -- Combine all information
    local all_macs = {}
    for mac in pairs(arp_cache) do all_macs[mac] = true end
    for mac in pairs(leases) do all_macs[mac] = true end
    for mac in pairs(wireless_clients) do all_macs[mac] = true end
    
    for mac in pairs(all_macs) do
        local client = {
            mac = mac,
            ip = arp_cache[mac] or (leases[mac] and leases[mac].ip),
            hostname = leases[mac] and leases[mac].hostname,
            lease_expiry = leases[mac] and leases[mac].expiry,
            connection_type = wireless_clients[mac] and "wireless" or "wired",
            wireless_info = wireless_clients[mac]
        }
        
        -- Get traffic statistics
        if client.ip then
            local rx, tx = M.get_client_traffic(client.ip)
            client.rx_bytes = rx
            client.tx_bytes = tx
        end
        
        table.insert(clients, client)
    end
    
    return clients
end

-- Get connected clients count
function M.get_connected_clients_count()
    local clients = M.get_connected_clients()
    return #clients
end

-- Get client traffic statistics
function M.get_client_traffic(ip)
    local rx_bytes, tx_bytes = 0, 0
    
    -- Try to get traffic from iptables accounting
    local output = exec_command("iptables -t mangle -L FORWARD -v -n -x 2>/dev/null")
    if output then
        for line in output:gmatch("[^\n]+") do
            if line:match(ip) then
                local pkts, bytes = line:match("^%s*(%d+)%s+(%d+)")
                if bytes then
                    if line:match("src=" .. ip) then
                        tx_bytes = tx_bytes + tonumber(bytes)
                    elseif line:match("dst=" .. ip) then
                        rx_bytes = rx_bytes + tonumber(bytes)
                    end
                end
            end
        end
    end
    
    return rx_bytes, tx_bytes
end

-- Get DHCP leases
function M.get_dhcp_leases()
    local leases = {}
    local lease_file = "/tmp/dhcp.leases"
    
    local f = io.open(lease_file, "r")
    if f then
        for line in f:lines() do
            local expiry, mac, ip, hostname, client_id = line:match("(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s*(%S*)")
            if mac then
                table.insert(leases, {
                    mac = mac,
                    ip = ip,
                    hostname = hostname ~= "*" and hostname or nil,
                    expiry = tonumber(expiry),
                    client_id = client_id ~= "" and client_id or nil,
                    remaining = tonumber(expiry) - os.time()
                })
            end
        end
        f:close()
    end
    
    return leases
end

-- Block client by MAC address
function M.block_client(mac)
    if not mac or not mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
        return nil, "Invalid MAC address"
    end
    
    -- Add firewall rule to block the MAC
    local rule_name = "block_" .. mac:gsub(":", "")
    
    -- Check if rule already exists
    local exists = false
    uci:foreach("firewall", "rule", function(s)
        if s.name == rule_name then
            exists = true
            return false
        end
    end)
    
    if not exists then
        local section = uci:add("firewall", "rule")
        uci:set("firewall", section, "name", rule_name)
        uci:set("firewall", section, "src", "lan")
        uci:set("firewall", section, "src_mac", mac)
        uci:set("firewall", section, "dest", "wan")
        uci:set("firewall", section, "proto", "all")
        uci:set("firewall", section, "target", "REJECT")
        
        uci:commit("firewall")
        os.execute("/etc/init.d/firewall restart")
    end
    
    return true
end

-- Get VPN status
function M.get_vpn_status()
    local status = {
        connected = false,
        type = nil,
        server = nil,
        local_ip = nil,
        remote_ip = nil,
        uptime = 0
    }
    
    -- Check OpenVPN
    local ovpn_status = exec_command("pidof openvpn")
    if ovpn_status and ovpn_status:match("%d+") then
        status.connected = true
        status.type = "openvpn"
        
        -- Get OpenVPN status
        local ovpn_info = exec_command("cat /tmp/openvpn-status.log 2>/dev/null")
        if ovpn_info then
            local remote = ovpn_info:match("TCP/UDP read bytes,(%S+)")
            if remote then
                status.server = remote
            end
        end
    end
    
    -- Check WireGuard
    local wg_status = exec_command("wg show 2>/dev/null")
    if wg_status and wg_status ~= "" then
        status.connected = true
        status.type = "wireguard"
        
        local endpoint = wg_status:match("endpoint: ([%d%.]+:%d+)")
        if endpoint then
            status.server = endpoint
        end
    end
    
    return status
end

-- Get VPN profiles
function M.get_vpn_profiles()
    local profiles = {}
    
    -- OpenVPN profiles
    local ovpn_dir = "/etc/openvpn"
    local files = exec_command("ls " .. ovpn_dir .. "/*.ovpn 2>/dev/null")
    if files then
        for file in files:gmatch("[^\n]+") do
            local name = file:match("([^/]+)%.ovpn$")
            if name then
                table.insert(profiles, {
                    name = name,
                    type = "openvpn",
                    path = file
                })
            end
        end
    end
    
    -- WireGuard profiles
    uci:foreach("network", "interface", function(s)
        if s.proto == "wireguard" then
            table.insert(profiles, {
                name = s[".name"],
                type = "wireguard",
                interface = s[".name"]
            })
        end
    end)
    
    return profiles
end

-- Connect VPN
function M.connect_vpn(profile)
    if not profile then
        return nil, "No profile specified"
    end
    
    -- Disconnect any existing VPN first
    M.disconnect_vpn()
    
    if profile.type == "openvpn" and profile.path then
        os.execute("openvpn --daemon --config " .. profile.path)
        return true
    elseif profile.type == "wireguard" and profile.interface then
        os.execute("ifup " .. profile.interface)
        return true
    end
    
    return nil, "Invalid VPN profile"
end

-- Disconnect VPN
function M.disconnect_vpn()
    -- Stop OpenVPN
    os.execute("killall openvpn 2>/dev/null")
    
    -- Stop WireGuard interfaces
    uci:foreach("network", "interface", function(s)
        if s.proto == "wireguard" then
            os.execute("ifdown " .. s[".name"])
        end
    end)
    
    return true
end

-- Get traffic statistics
function M.get_traffic_stats()
    local stats = {
        interfaces = {}
    }
    
    -- Get stats for each interface
    local ifaces = {"wan", "lan", "wlan0"}
    for _, iface in ipairs(ifaces) do
        local if_stats = {}
        
        local info = exec_command("ifconfig " .. iface .. " 2>/dev/null")
        if info then
            local rx_bytes = info:match("RX bytes:(%d+)")
            local tx_bytes = info:match("TX bytes:(%d+)")
            local rx_packets = info:match("RX packets:(%d+)")
            local tx_packets = info:match("TX packets:(%d+)")
            
            if_stats = {
                name = iface,
                rx_bytes = tonumber(rx_bytes) or 0,
                tx_bytes = tonumber(tx_bytes) or 0,
                rx_packets = tonumber(rx_packets) or 0,
                tx_packets = tonumber(tx_packets) or 0
            }
            
            stats.interfaces[iface] = if_stats
        end
    end
    
    return stats
end

-- Get real-time traffic
function M.get_realtime_traffic()
    local traffic = {
        timestamp = os.time(),
        interfaces = {}
    }
    
    -- Read from /proc/net/dev for real-time stats
    local f = io.open("/proc/net/dev", "r")
    if f then
        for line in f:lines() do
            local iface, rx_bytes, rx_packets, tx_bytes, tx_packets = 
                line:match("^%s*(%S+):%s*(%d+)%s+(%d+)%s+%d+%s+%d+%s+%d+%s+%d+%s+%d+%s+%d+%s+(%d+)%s+(%d+)")
            
            if iface and (iface == "wan" or iface == "lan" or iface == "wlan0") then
                traffic.interfaces[iface] = {
                    rx_bytes = tonumber(rx_bytes),
                    rx_packets = tonumber(rx_packets),
                    tx_bytes = tonumber(tx_bytes),
                    tx_packets = tonumber(tx_packets)
                }
            end
        end
        f:close()
    end
    
    return traffic
end

return M