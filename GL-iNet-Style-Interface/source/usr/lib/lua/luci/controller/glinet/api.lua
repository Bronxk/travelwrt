-- GL.iNet Style Interface API Controller
-- api.lua - REST API endpoints for the web interface

local sys = require "luci.sys"
local json = require "luci.jsonc"
local uci = require "luci.model.uci".cursor()
local nixio = require "nixio"
local auth = require "luci.model.glinet.auth"
local network_model = require "luci.model.glinet.network"
local system_model = require "luci.model.glinet.system"

-- Initialize authentication
auth.init()

-- Helper functions
local function send_response(data, status)
    status = status or 200
    
    print("Status: " .. status)
    print("Content-Type: application/json")
    print("Cache-Control: no-cache, no-store, must-revalidate")
    print("")
    
    if type(data) == "table" then
        print(json.stringify(data))
    else
        print(json.stringify({ message = tostring(data) }))
    end
end

local function parse_request_body()
    local content_length = tonumber(os.getenv("CONTENT_LENGTH") or 0)
    if content_length > 0 then
        local body = io.read(content_length)
        return json.parse(body)
    end
    return {}
end

local function get_request_method()
    return os.getenv("REQUEST_METHOD") or "GET"
end

local function get_path_info()
    return os.getenv("PATH_INFO") or ""
end

-- CORS headers for development
local function send_cors_headers()
    print("Access-Control-Allow-Origin: *")
    print("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS")
    print("Access-Control-Allow-Headers: Content-Type, Authorization")
end

-- API Routes
local routes = {}

-- Authentication endpoints
routes["POST /auth/login"] = function()
    local body = parse_request_body()
    
    if not body.username or not body.password then
        return send_response("Missing username or password", 400)
    end
    
    local result, err = auth.authenticate(body.username, body.password)
    if not result then
        return send_response(err or "Authentication failed", 401)
    end
    
    send_response(result)
end

routes["POST /auth/refresh"] = function()
    local body = parse_request_body()
    
    if not body.refresh_token then
        return send_response("Missing refresh token", 400)
    end
    
    local result, err = auth.refresh_token(body.refresh_token)
    if not result then
        return send_response(err or "Invalid refresh token", 401)
    end
    
    send_response(result)
end

routes["POST /auth/logout"] = auth.require_auth()(function(user)
    local auth_header = os.getenv("HTTP_AUTHORIZATION")
    auth.logout(auth_header)
    send_response({ message = "Logged out successfully" })
end)

routes["POST /auth/change-password"] = auth.require_auth()(function(user, body)
    body = parse_request_body()
    
    if not body.old_password or not body.new_password then
        return send_response("Missing required fields", 400)
    end
    
    local result, err = auth.change_password(user.username, body.old_password, body.new_password)
    if not result then
        return send_response(err or "Failed to change password", 400)
    end
    
    send_response({ message = "Password changed successfully" })
end)

-- System information endpoints
routes["GET /system/info"] = auth.require_auth()(function(user)
    local info = {
        hostname = sys.hostname(),
        model = system_model.get_model(),
        firmware = system_model.get_firmware_version(),
        kernel = sys.exec("uname -r"):trim(),
        uptime = system_model.get_uptime(),
        load = { sys.loadavg() },
        memory = system_model.get_memory_info(),
        storage = system_model.get_storage_info(),
        cpu = system_model.get_cpu_info()
    }
    
    send_response(info)
end)

routes["GET /system/status"] = auth.require_auth()(function(user)
    local status = {
        system = {
            uptime = system_model.get_uptime_seconds(),
            load = { sys.loadavg() },
            cpu_usage = system_model.get_cpu_usage(),
            memory_usage = system_model.get_memory_usage()
        },
        network = {
            wan_status = network_model.get_wan_status(),
            lan_status = network_model.get_lan_status(),
            clients = network_model.get_connected_clients_count()
        },
        services = system_model.get_services_status()
    }
    
    send_response(status)
end)

-- Network endpoints
routes["GET /network/interfaces"] = auth.require_auth()(function(user)
    local interfaces = network_model.get_interfaces()
    send_response(interfaces)
end)

routes["GET /network/wan/status"] = auth.require_auth()(function(user)
    local status = network_model.get_wan_status()
    send_response(status)
end)

routes["POST /network/wan/connect"] = auth.require_auth("admin")(function(user)
    local body = parse_request_body()
    local result, err = network_model.configure_wan(body)
    
    if not result then
        return send_response(err or "Failed to configure WAN", 400)
    end
    
    send_response({ message = "WAN configured successfully" })
end)

routes["GET /network/lan/status"] = auth.require_auth()(function(user)
    local status = network_model.get_lan_status()
    send_response(status)
end)

routes["POST /network/lan/configure"] = auth.require_auth("admin")(function(user)
    local body = parse_request_body()
    local result, err = network_model.configure_lan(body)
    
    if not result then
        return send_response(err or "Failed to configure LAN", 400)
    end
    
    send_response({ message = "LAN configured successfully" })
end)

-- Wireless endpoints
routes["GET /wireless/status"] = auth.require_auth()(function(user)
    local status = network_model.get_wireless_status()
    send_response(status)
end)

routes["GET /wireless/scan"] = auth.require_auth()(function(user)
    local networks = network_model.scan_wireless()
    send_response(networks)
end)

routes["POST /wireless/configure"] = auth.require_auth("admin")(function(user)
    local body = parse_request_body()
    local result, err = network_model.configure_wireless(body)
    
    if not result then
        return send_response(err or "Failed to configure wireless", 400)
    end
    
    send_response({ message = "Wireless configured successfully" })
end)

-- Client management endpoints
routes["GET /clients/connected"] = auth.require_auth()(function(user)
    local clients = network_model.get_connected_clients()
    send_response(clients)
end)

routes["GET /clients/dhcp-leases"] = auth.require_auth()(function(user)
    local leases = network_model.get_dhcp_leases()
    send_response(leases)
end)

routes["POST /clients/block"] = auth.require_auth("admin")(function(user)
    local body = parse_request_body()
    
    if not body.mac then
        return send_response("Missing MAC address", 400)
    end
    
    local result, err = network_model.block_client(body.mac)
    if not result then
        return send_response(err or "Failed to block client", 400)
    end
    
    send_response({ message = "Client blocked successfully" })
end)

-- VPN endpoints
routes["GET /vpn/status"] = auth.require_auth()(function(user)
    local status = network_model.get_vpn_status()
    send_response(status)
end)

routes["GET /vpn/profiles"] = auth.require_auth()(function(user)
    local profiles = network_model.get_vpn_profiles()
    send_response(profiles)
end)

routes["POST /vpn/connect"] = auth.require_auth("admin")(function(user)
    local body = parse_request_body()
    
    if not body.profile then
        return send_response("Missing VPN profile", 400)
    end
    
    local result, err = network_model.connect_vpn(body.profile)
    if not result then
        return send_response(err or "Failed to connect VPN", 400)
    end
    
    send_response({ message = "VPN connected successfully" })
end)

routes["POST /vpn/disconnect"] = auth.require_auth("admin")(function(user)
    local result, err = network_model.disconnect_vpn()
    if not result then
        return send_response(err or "Failed to disconnect VPN", 400)
    end
    
    send_response({ message = "VPN disconnected successfully" })
end)

-- System management endpoints
routes["GET /system/logs"] = auth.require_auth("admin")(function(user)
    local logs = system_model.get_system_logs()
    send_response(logs)
end)

routes["POST /system/reboot"] = auth.require_auth("admin")(function(user)
    send_response({ message = "System will reboot in 5 seconds" })
    os.execute("(sleep 5 && reboot) &")
end)

routes["POST /system/factory-reset"] = auth.require_auth("admin")(function(user)
    send_response({ message = "System will reset to factory defaults in 5 seconds" })
    os.execute("(sleep 5 && firstboot -y && reboot) &")
end)

routes["GET /system/backup"] = auth.require_auth("admin")(function(user)
    local backup_data = system_model.create_backup()
    
    print("Content-Type: application/octet-stream")
    print("Content-Disposition: attachment; filename=\"backup-" .. os.date("%Y%m%d-%H%M%S") .. ".tar.gz\"")
    print("")
    io.write(backup_data)
end)

routes["POST /system/restore"] = auth.require_auth("admin")(function(user)
    -- Handle file upload
    local content_type = os.getenv("CONTENT_TYPE") or ""
    if not content_type:match("multipart/form%-data") then
        return send_response("Invalid content type", 400)
    end
    
    -- Parse multipart data (simplified version)
    local content_length = tonumber(os.getenv("CONTENT_LENGTH") or 0)
    if content_length > 0 then
        local data = io.read(content_length)
        -- Extract file data from multipart
        -- This is a simplified version - in production, use proper multipart parser
        
        local result, err = system_model.restore_backup(data)
        if not result then
            return send_response(err or "Failed to restore backup", 400)
        end
        
        send_response({ message = "Backup restored successfully. System will reboot." })
        os.execute("(sleep 5 && reboot) &")
    else
        send_response("No file uploaded", 400)
    end
end)

-- Firmware update endpoints
routes["GET /system/firmware/check"] = auth.require_auth("admin")(function(user)
    local updates = system_model.check_firmware_updates()
    send_response(updates)
end)

routes["POST /system/firmware/upgrade"] = auth.require_auth("admin")(function(user)
    local body = parse_request_body()
    
    if not body.version then
        return send_response("Missing firmware version", 400)
    end
    
    local result, err = system_model.upgrade_firmware(body.version)
    if not result then
        return send_response(err or "Failed to upgrade firmware", 400)
    end
    
    send_response({ message = "Firmware upgrade started" })
end)

-- Traffic statistics endpoints
routes["GET /stats/traffic"] = auth.require_auth()(function(user)
    local stats = network_model.get_traffic_stats()
    send_response(stats)
end)

routes["GET /stats/traffic/realtime"] = auth.require_auth()(function(user)
    local stats = network_model.get_realtime_traffic()
    send_response(stats)
end)

-- Main request handler
local function handle_request()
    local method = get_request_method()
    local path = get_path_info()
    
    -- Handle CORS preflight
    if method == "OPTIONS" then
        send_cors_headers()
        print("Status: 204")
        print("")
        return
    end
    
    -- Add CORS headers to all responses
    send_cors_headers()
    
    -- Find matching route
    local route_key = method .. " " .. path
    local handler = routes[route_key]
    
    if handler then
        local ok, err = pcall(handler)
        if not ok then
            send_response("Internal server error: " .. tostring(err), 500)
        end
    else
        -- Try pattern matching for dynamic routes
        local handled = false
        for pattern, handler in pairs(routes) do
            local method_pattern, path_pattern = pattern:match("^(%S+)%s+(.+)$")
            if method_pattern == method then
                local captures = { path:match(path_pattern) }
                if #captures > 0 then
                    local ok, err = pcall(handler, unpack(captures))
                    if not ok then
                        send_response("Internal server error: " .. tostring(err), 500)
                    end
                    handled = true
                    break
                end
            end
        end
        
        if not handled then
            send_response("Not found", 404)
        end
    end
end

-- WebSocket support for real-time updates
local function handle_websocket()
    -- This would be implemented with a separate WebSocket server
    -- For now, we'll use Server-Sent Events as a simpler alternative
    
    if get_path_info() == "/events" then
        print("Content-Type: text/event-stream")
        print("Cache-Control: no-cache")
        print("Connection: keep-alive")
        print("")
        
        -- Send events
        while true do
            local event_data = {
                type = "status",
                data = {
                    cpu = system_model.get_cpu_usage(),
                    memory = system_model.get_memory_usage(),
                    traffic = network_model.get_realtime_traffic()
                }
            }
            
            print("data: " .. json.stringify(event_data))
            print("")
            io.flush()
            
            nixio.sleep(2)
        end
    end
end

-- Entry point
handle_request()