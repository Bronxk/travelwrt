-- GL.iNet Style Interface System Model
-- system.lua - System management functions

local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()
local nixio = require "nixio"
local json = require "luci.jsonc"

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

-- Get router model
function M.get_model()
    local model = "Unknown"
    
    -- Try to get model from /proc/cpuinfo
    local cpuinfo = exec_command("cat /proc/cpuinfo")
    if cpuinfo then
        model = cpuinfo:match("machine%s*:%s*([^\n]+)") or model
    end
    
    -- Try to get from /tmp/sysinfo/model
    local f = io.open("/tmp/sysinfo/model", "r")
    if f then
        model = f:read("*l") or model
        f:close()
    end
    
    -- Try board name
    f = io.open("/tmp/sysinfo/board_name", "r")
    if f then
        model = f:read("*l") or model
        f:close()
    end
    
    return model:trim()
end

-- Get firmware version
function M.get_firmware_version()
    local version = "Unknown"
    
    -- Try to get from /etc/openwrt_release
    local f = io.open("/etc/openwrt_release", "r")
    if f then
        local content = f:read("*a")
        f:close()
        
        version = content:match('DISTRIB_RELEASE="([^"]+)"') or version
        local revision = content:match('DISTRIB_REVISION="([^"]+)"')
        if revision then
            version = version .. " " .. revision
        end
    end
    
    return version
end

-- Get uptime string
function M.get_uptime()
    local uptime = sys.uptime()
    local days = math.floor(uptime / 86400)
    local hours = math.floor((uptime % 86400) / 3600)
    local minutes = math.floor((uptime % 3600) / 60)
    
    if days > 0 then
        return string.format("%dd %dh %dm", days, hours, minutes)
    elseif hours > 0 then
        return string.format("%dh %dm", hours, minutes)
    else
        return string.format("%dm", minutes)
    end
end

-- Get uptime in seconds
function M.get_uptime_seconds()
    return sys.uptime()
end

-- Get CPU information
function M.get_cpu_info()
    local info = {
        model = "Unknown",
        cores = 1,
        frequency = "Unknown"
    }
    
    local cpuinfo = exec_command("cat /proc/cpuinfo")
    if cpuinfo then
        -- CPU model
        info.model = cpuinfo:match("model name%s*:%s*([^\n]+)") or 
                    cpuinfo:match("Processor%s*:%s*([^\n]+)") or 
                    cpuinfo:match("cpu model%s*:%s*([^\n]+)") or 
                    "Unknown"
        
        -- Count cores
        local cores = 0
        for _ in cpuinfo:gmatch("processor%s*:") do
            cores = cores + 1
        end
        info.cores = cores > 0 and cores or 1
        
        -- CPU frequency
        local freq = cpuinfo:match("cpu MHz%s*:%s*([%d%.]+)")
        if freq then
            info.frequency = string.format("%.0f MHz", tonumber(freq))
        end
    end
    
    -- Try to get current frequency
    local cur_freq = exec_command("cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq 2>/dev/null")
    if cur_freq then
        local freq_mhz = tonumber(cur_freq) / 1000
        info.frequency = string.format("%.0f MHz", freq_mhz)
    end
    
    return info
end

-- Get CPU usage
function M.get_cpu_usage()
    local cpu_usage = 0
    
    -- Read /proc/stat twice with a small delay
    local function read_cpu_stats()
        local f = io.open("/proc/stat", "r")
        if not f then return nil end
        
        local line = f:read("*l")
        f:close()
        
        local user, nice, system, idle, iowait, irq, softirq = 
            line:match("cpu%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)")
        
        if user then
            local total = tonumber(user) + tonumber(nice) + tonumber(system) + 
                         tonumber(idle) + tonumber(iowait) + tonumber(irq) + tonumber(softirq)
            local active = total - tonumber(idle) - tonumber(iowait)
            return active, total
        end
        
        return nil
    end
    
    local active1, total1 = read_cpu_stats()
    if active1 then
        nixio.nanosleep(0, 100000000) -- 100ms
        local active2, total2 = read_cpu_stats()
        
        if active2 and total2 > total1 then
            cpu_usage = math.floor(((active2 - active1) * 100) / (total2 - total1))
        end
    end
    
    return cpu_usage
end

-- Get memory information
function M.get_memory_info()
    local meminfo = {
        total = 0,
        free = 0,
        used = 0,
        buffered = 0,
        cached = 0,
        available = 0
    }
    
    local f = io.open("/proc/meminfo", "r")
    if f then
        for line in f:lines() do
            local key, value = line:match("^([^:]+):%s*(%d+)")
            if key and value then
                value = tonumber(value) * 1024 -- Convert from KB to bytes
                
                if key == "MemTotal" then
                    meminfo.total = value
                elseif key == "MemFree" then
                    meminfo.free = value
                elseif key == "Buffers" then
                    meminfo.buffered = value
                elseif key == "Cached" then
                    meminfo.cached = value
                elseif key == "MemAvailable" then
                    meminfo.available = value
                end
            end
        end
        f:close()
        
        -- Calculate used memory
        if meminfo.available > 0 then
            meminfo.used = meminfo.total - meminfo.available
        else
            -- Fallback calculation
            meminfo.used = meminfo.total - meminfo.free - meminfo.buffered - meminfo.cached
        end
    end
    
    return meminfo
end

-- Get memory usage percentage
function M.get_memory_usage()
    local info = M.get_memory_info()
    if info.total > 0 then
        return math.floor((info.used * 100) / info.total)
    end
    return 0
end

-- Get storage information
function M.get_storage_info()
    local storage = {}
    
    local df_output = exec_command("df -h")
    if df_output then
        for line in df_output:gmatch("[^\n]+") do
            local fs, size, used, available, percent, mount = 
                line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(.+)$")
            
            if fs and mount and not fs:match("^tmpfs") and not fs:match("^devtmpfs") then
                table.insert(storage, {
                    filesystem = fs,
                    size = size,
                    used = used,
                    available = available,
                    percent = percent,
                    mount = mount
                })
            end
        end
    end
    
    return storage
end

-- Get services status
function M.get_services_status()
    local services = {
        uhttpd = false,
        dnsmasq = false,
        dropbear = false,
        firewall = false,
        network = false
    }
    
    for service, _ in pairs(services) do
        local status = exec_command("/etc/init.d/" .. service .. " status 2>/dev/null")
        if status and status:match("running") then
            services[service] = true
        end
    end
    
    return services
end

-- Get system logs
function M.get_system_logs(lines)
    lines = lines or 100
    local logs = {}
    
    -- System log
    local syslog = exec_command("logread -l " .. lines .. " 2>/dev/null")
    if syslog then
        for line in syslog:gmatch("[^\n]+") do
            table.insert(logs, {
                type = "system",
                message = line
            })
        end
    end
    
    -- Kernel log
    local dmesg = exec_command("dmesg | tail -n " .. math.floor(lines/2) .. " 2>/dev/null")
    if dmesg then
        for line in dmesg:gmatch("[^\n]+") do
            table.insert(logs, {
                type = "kernel",
                message = line
            })
        end
    end
    
    return logs
end

-- Create system backup
function M.create_backup()
    local backup_files = {
        "/etc/config/",
        "/etc/dropbear/",
        "/etc/uhttpd.crt",
        "/etc/uhttpd.key",
        "/etc/sysupgrade.conf",
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow"
    }
    
    -- Create temporary directory
    local tmp_dir = "/tmp/backup-" .. os.time()
    os.execute("mkdir -p " .. tmp_dir)
    
    -- Copy files to backup
    for _, file in ipairs(backup_files) do
        os.execute("cp -a " .. file .. " " .. tmp_dir .. "/ 2>/dev/null")
    end
    
    -- Create tarball
    local backup_file = "/tmp/backup.tar.gz"
    os.execute("cd /tmp && tar czf " .. backup_file .. " " .. tmp_dir:match("([^/]+)$"))
    
    -- Read backup file
    local f = io.open(backup_file, "rb")
    local data = nil
    if f then
        data = f:read("*a")
        f:close()
    end
    
    -- Cleanup
    os.execute("rm -rf " .. tmp_dir)
    os.execute("rm -f " .. backup_file)
    
    return data
end

-- Restore system backup
function M.restore_backup(backup_data)
    if not backup_data or #backup_data == 0 then
        return nil, "Invalid backup data"
    end
    
    -- Write backup to temporary file
    local backup_file = "/tmp/restore-backup.tar.gz"
    local f = io.open(backup_file, "wb")
    if not f then
        return nil, "Failed to write backup file"
    end
    
    f:write(backup_data)
    f:close()
    
    -- Extract backup
    local tmp_dir = "/tmp/restore-" .. os.time()
    os.execute("mkdir -p " .. tmp_dir)
    
    local result = os.execute("cd " .. tmp_dir .. " && tar xzf " .. backup_file .. " 2>/dev/null")
    if result ~= 0 then
        os.execute("rm -rf " .. tmp_dir)
        os.execute("rm -f " .. backup_file)
        return nil, "Failed to extract backup"
    end
    
    -- Find the backup directory
    local backup_dir = exec_command("ls -d " .. tmp_dir .. "/backup-* 2>/dev/null | head -n1")
    if not backup_dir or backup_dir == "" then
        os.execute("rm -rf " .. tmp_dir)
        os.execute("rm -f " .. backup_file)
        return nil, "Invalid backup format"
    end
    
    backup_dir = backup_dir:trim()
    
    -- Restore files
    os.execute("cp -a " .. backup_dir .. "/config/* /etc/config/ 2>/dev/null")
    os.execute("cp -a " .. backup_dir .. "/dropbear/* /etc/dropbear/ 2>/dev/null")
    os.execute("cp -a " .. backup_dir .. "/uhttpd.* /etc/ 2>/dev/null")
    os.execute("cp -a " .. backup_dir .. "/passwd /etc/ 2>/dev/null")
    os.execute("cp -a " .. backup_dir .. "/group /etc/ 2>/dev/null")
    os.execute("cp -a " .. backup_dir .. "/shadow /etc/ 2>/dev/null")
    
    -- Cleanup
    os.execute("rm -rf " .. tmp_dir)
    os.execute("rm -f " .. backup_file)
    
    return true
end

-- Check for firmware updates
function M.check_firmware_updates()
    local updates = {
        current_version = M.get_firmware_version(),
        available = false,
        latest_version = nil,
        release_notes = nil
    }
    
    -- In a real implementation, this would check an update server
    -- For now, we'll simulate the check
    local model = M.get_model()
    
    -- Simulated update check
    -- You would replace this with actual HTTP request to update server
    local update_info = exec_command("opkg update && opkg list-upgradable 2>/dev/null")
    if update_info and update_info ~= "" then
        updates.available = true
        updates.packages = {}
        
        for line in update_info:gmatch("[^\n]+") do
            local pkg, old_ver, new_ver = line:match("^(%S+)%s+%-%s+(%S+)%s+%-%s+(%S+)")
            if pkg then
                table.insert(updates.packages, {
                    name = pkg,
                    current = old_ver,
                    available = new_ver
                })
            end
        end
    end
    
    return updates
end

-- Upgrade firmware
function M.upgrade_firmware(version, keep_settings)
    keep_settings = keep_settings ~= false  -- Default to true
    
    -- In a real implementation, this would:
    -- 1. Download the firmware image
    -- 2. Verify checksum
    -- 3. Run sysupgrade
    
    -- For now, we'll return a simulated response
    return nil, "Firmware upgrade not implemented in demo"
end

-- Get temperature sensors
function M.get_temperature()
    local temps = {}
    
    -- Try thermal zones
    local thermal_zones = exec_command("ls /sys/class/thermal/thermal_zone*/temp 2>/dev/null")
    if thermal_zones then
        for zone in thermal_zones:gmatch("[^\n]+") do
            local temp = exec_command("cat " .. zone .. " 2>/dev/null")
            if temp then
                local zone_num = zone:match("thermal_zone(%d+)")
                local temp_c = tonumber(temp) / 1000
                table.insert(temps, {
                    sensor = "thermal_zone" .. zone_num,
                    temperature = temp_c,
                    unit = "°C"
                })
            end
        end
    end
    
    -- Try hwmon sensors
    local hwmon = exec_command("ls /sys/class/hwmon/hwmon*/temp*_input 2>/dev/null")
    if hwmon then
        for sensor in hwmon:gmatch("[^\n]+") do
            local temp = exec_command("cat " .. sensor .. " 2>/dev/null")
            if temp then
                local sensor_name = sensor:match("hwmon(%d+)/temp(%d+)")
                local temp_c = tonumber(temp) / 1000
                table.insert(temps, {
                    sensor = "hwmon" .. sensor_name,
                    temperature = temp_c,
                    unit = "°C"
                })
            end
        end
    end
    
    return temps
end

-- Get LED status
function M.get_led_status()
    local leds = {}
    
    local led_list = exec_command("ls /sys/class/leds/ 2>/dev/null")
    if led_list then
        for led in led_list:gmatch("[^\n]+") do
            local brightness = exec_command("cat /sys/class/leds/" .. led .. "/brightness 2>/dev/null")
            local max_brightness = exec_command("cat /sys/class/leds/" .. led .. "/max_brightness 2>/dev/null")
            
            if brightness and max_brightness then
                table.insert(leds, {
                    name = led,
                    brightness = tonumber(brightness) or 0,
                    max_brightness = tonumber(max_brightness) or 255,
                    on = tonumber(brightness) > 0
                })
            end
        end
    end
    
    return leds
end

-- Set LED state
function M.set_led(led_name, state)
    if not led_name then
        return nil, "LED name required"
    end
    
    local led_path = "/sys/class/leds/" .. led_name .. "/brightness"
    local f = io.open(led_path, "w")
    if not f then
        return nil, "LED not found"
    end
    
    if state then
        -- Get max brightness
        local max_bright = exec_command("cat /sys/class/leds/" .. led_name .. "/max_brightness 2>/dev/null")
        f:write(max_bright or "255")
    else
        f:write("0")
    end
    
    f:close()
    return true
end

-- Get USB devices
function M.get_usb_devices()
    local devices = {}
    
    local lsusb = exec_command("lsusb 2>/dev/null")
    if lsusb then
        for line in lsusb:gmatch("[^\n]+") do
            local bus, device, id, desc = line:match("Bus (%d+) Device (%d+): ID (%S+)%s+(.+)")
            if bus then
                table.insert(devices, {
                    bus = bus,
                    device = device,
                    id = id,
                    description = desc
                })
            end
        end
    end
    
    return devices
end

return M