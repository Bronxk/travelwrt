-- GL.iNet Style Interface Authentication Module
-- auth.lua - JWT-based authentication system

local nixio = require "nixio"
local json = require "luci.jsonc"
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

local M = {}

-- Configuration
local JWT_SECRET = nil -- Will be generated on first run
local JWT_EXPIRY = 1800 -- 30 minutes
local REFRESH_TOKEN_EXPIRY = 86400 * 7 -- 7 days
local MAX_LOGIN_ATTEMPTS = 5
local LOCKOUT_DURATION = 300 -- 5 minutes

-- Initialize JWT secret
local function init_jwt_secret()
    local secret = uci:get("glinet_interface", "auth", "jwt_secret")
    if not secret then
        -- Generate a new secret
        local fd = io.open("/dev/urandom", "rb")
        if fd then
            secret = nixio.bin.b64encode(fd:read(32))
            fd:close()
            
            uci:set("glinet_interface", "auth", "jwt_secret", secret)
            uci:commit("glinet_interface")
        end
    end
    JWT_SECRET = secret
    return secret ~= nil
end

-- Base64 URL encoding/decoding
local function base64_url_encode(data)
    local b64 = nixio.bin.b64encode(data)
    return b64:gsub('+', '-'):gsub('/', '_'):gsub('=', '')
end

local function base64_url_decode(data)
    data = data:gsub('-', '+'):gsub('_', '/')
    local padding = (4 - #data % 4) % 4
    return nixio.bin.b64decode(data .. string.rep('=', padding))
end

-- HMAC-SHA256 implementation
local function hmac_sha256(key, data)
    local crypto = require "luci.sys.crypto"
    return crypto.hmac_sha256(key, data)
end

-- JWT functions
local function create_jwt_token(payload)
    if not JWT_SECRET then
        if not init_jwt_secret() then
            return nil, "Failed to initialize JWT secret"
        end
    end
    
    -- Add standard claims
    payload.iat = os.time()
    payload.exp = os.time() + JWT_EXPIRY
    
    -- Create header
    local header = {
        alg = "HS256",
        typ = "JWT"
    }
    
    -- Encode parts
    local header_encoded = base64_url_encode(json.stringify(header))
    local payload_encoded = base64_url_encode(json.stringify(payload))
    
    -- Create signature
    local data = header_encoded .. "." .. payload_encoded
    local signature = base64_url_encode(hmac_sha256(JWT_SECRET, data))
    
    return data .. "." .. signature
end

local function verify_jwt_token(token)
    if not JWT_SECRET then
        if not init_jwt_secret() then
            return nil, "JWT secret not initialized"
        end
    end
    
    -- Split token
    local parts = {}
    for part in token:gmatch("[^.]+") do
        table.insert(parts, part)
    end
    
    if #parts ~= 3 then
        return nil, "Invalid token format"
    end
    
    -- Verify signature
    local data = parts[1] .. "." .. parts[2]
    local signature = base64_url_encode(hmac_sha256(JWT_SECRET, data))
    
    if signature ~= parts[3] then
        return nil, "Invalid signature"
    end
    
    -- Decode payload
    local payload_json = base64_url_decode(parts[2])
    local payload = json.parse(payload_json)
    
    if not payload then
        return nil, "Invalid payload"
    end
    
    -- Check expiration
    if payload.exp and payload.exp < os.time() then
        return nil, "Token expired"
    end
    
    return payload
end

-- User management functions
local function hash_password(password, salt)
    if not salt then
        -- Generate salt
        local fd = io.open("/dev/urandom", "rb")
        if fd then
            salt = nixio.bin.hexlify(fd:read(16))
            fd:close()
        else
            salt = tostring(os.time())
        end
    end
    
    local crypto = require "luci.sys.crypto"
    local hash = crypto.sha256(salt .. password)
    
    return hash, salt
end

local function verify_password(password, stored_hash, salt)
    local hash = hash_password(password, salt)
    return hash == stored_hash
end

-- Login attempt tracking
local login_attempts = {}

local function track_login_attempt(username, success)
    if not login_attempts[username] then
        login_attempts[username] = {
            count = 0,
            last_attempt = 0,
            locked_until = 0
        }
    end
    
    local user_attempts = login_attempts[username]
    
    if success then
        user_attempts.count = 0
        user_attempts.locked_until = 0
    else
        user_attempts.count = user_attempts.count + 1
        user_attempts.last_attempt = os.time()
        
        if user_attempts.count >= MAX_LOGIN_ATTEMPTS then
            user_attempts.locked_until = os.time() + LOCKOUT_DURATION
        end
    end
end

local function is_account_locked(username)
    if not login_attempts[username] then
        return false
    end
    
    local user_attempts = login_attempts[username]
    
    if user_attempts.locked_until > os.time() then
        return true, user_attempts.locked_until - os.time()
    end
    
    return false
end

-- Session management
local sessions = {}

local function create_session(username, role)
    local session_id = nixio.bin.hexlify(nixio.bin.random(16))
    
    sessions[session_id] = {
        username = username,
        role = role,
        created = os.time(),
        last_activity = os.time(),
        ip = os.getenv("REMOTE_ADDR")
    }
    
    return session_id
end

local function get_session(session_id)
    local session = sessions[session_id]
    
    if not session then
        return nil
    end
    
    -- Check session timeout
    if os.time() - session.last_activity > JWT_EXPIRY then
        sessions[session_id] = nil
        return nil
    end
    
    -- Update last activity
    session.last_activity = os.time()
    
    return session
end

local function destroy_session(session_id)
    sessions[session_id] = nil
end

-- Public API functions
function M.authenticate(username, password)
    -- Check if account is locked
    local locked, remaining = is_account_locked(username)
    if locked then
        return nil, string.format("Account locked. Try again in %d seconds", remaining)
    end
    
    -- Get user from UCI config
    local users = uci:get_all("glinet_interface", "users") or {}
    local user_data = nil
    
    uci:foreach("glinet_interface", "user", function(s)
        if s.username == username then
            user_data = s
            return false
        end
    end)
    
    if not user_data then
        track_login_attempt(username, false)
        return nil, "Invalid credentials"
    end
    
    -- Verify password
    if not verify_password(password, user_data.password, user_data.salt) then
        track_login_attempt(username, false)
        return nil, "Invalid credentials"
    end
    
    track_login_attempt(username, true)
    
    -- Create session
    local session_id = create_session(username, user_data.role or "user")
    
    -- Create tokens
    local access_token = create_jwt_token({
        sub = username,
        role = user_data.role or "user",
        session = session_id
    })
    
    local refresh_token = create_jwt_token({
        sub = username,
        type = "refresh",
        session = session_id,
        exp = os.time() + REFRESH_TOKEN_EXPIRY
    })
    
    return {
        access_token = access_token,
        refresh_token = refresh_token,
        expires_in = JWT_EXPIRY,
        role = user_data.role or "user"
    }
end

function M.verify_token(token)
    if not token then
        return nil, "No token provided"
    end
    
    -- Remove "Bearer " prefix if present
    token = token:gsub("^Bearer%s+", "")
    
    local payload, err = verify_jwt_token(token)
    if not payload then
        return nil, err
    end
    
    -- Verify session
    if payload.session then
        local session = get_session(payload.session)
        if not session then
            return nil, "Invalid session"
        end
        
        return {
            username = payload.sub,
            role = payload.role,
            session = session
        }
    end
    
    return payload
end

function M.refresh_token(refresh_token)
    local payload, err = verify_jwt_token(refresh_token)
    if not payload then
        return nil, err
    end
    
    if payload.type ~= "refresh" then
        return nil, "Invalid token type"
    end
    
    -- Create new access token
    local access_token = create_jwt_token({
        sub = payload.sub,
        role = payload.role,
        session = payload.session
    })
    
    return {
        access_token = access_token,
        expires_in = JWT_EXPIRY
    }
end

function M.logout(token)
    local payload = verify_jwt_token(token)
    if payload and payload.session then
        destroy_session(payload.session)
    end
    return true
end

function M.change_password(username, old_password, new_password)
    -- Verify old password first
    local auth_result = M.authenticate(username, old_password)
    if not auth_result then
        return nil, "Invalid current password"
    end
    
    -- Update password
    local hash, salt = hash_password(new_password)
    
    local updated = false
    uci:foreach("glinet_interface", "user", function(s)
        if s.username == username then
            uci:set("glinet_interface", s[".name"], "password", hash)
            uci:set("glinet_interface", s[".name"], "salt", salt)
            updated = true
            return false
        end
    end)
    
    if updated then
        uci:commit("glinet_interface")
        return true
    end
    
    return nil, "User not found"
end

function M.create_user(username, password, role)
    -- Check if user exists
    local exists = false
    uci:foreach("glinet_interface", "user", function(s)
        if s.username == username then
            exists = true
            return false
        end
    end)
    
    if exists then
        return nil, "User already exists"
    end
    
    -- Create user
    local hash, salt = hash_password(password)
    local section = uci:add("glinet_interface", "user")
    
    uci:set("glinet_interface", section, "username", username)
    uci:set("glinet_interface", section, "password", hash)
    uci:set("glinet_interface", section, "salt", salt)
    uci:set("glinet_interface", section, "role", role or "user")
    uci:set("glinet_interface", section, "created", os.time())
    
    uci:commit("glinet_interface")
    
    return true
end

function M.require_auth(role)
    return function(handler)
        return function(...)
            local auth_header = os.getenv("HTTP_AUTHORIZATION")
            if not auth_header then
                return {
                    status = 401,
                    message = "Authentication required"
                }
            end
            
            local user, err = M.verify_token(auth_header)
            if not user then
                return {
                    status = 401,
                    message = err or "Invalid token"
                }
            end
            
            -- Check role if specified
            if role and user.role ~= role and user.role ~= "admin" then
                return {
                    status = 403,
                    message = "Insufficient permissions"
                }
            end
            
            -- Call the handler with user context
            return handler(user, ...)
        end
    end
end

-- Initialize default admin user if none exists
function M.init()
    init_jwt_secret()
    
    local has_admin = false
    uci:foreach("glinet_interface", "user", function(s)
        if s.role == "admin" then
            has_admin = true
            return false
        end
    end)
    
    if not has_admin then
        M.create_user("admin", "admin", "admin")
    end
end

return M