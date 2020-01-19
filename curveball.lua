local parserName = "curveball_lua"
local parserVersion = "2020.01.18"

local tlsParser = nw.createParser(parserName, "CVE-2020-0601 (curveball) inspect")

-- nw.logInfo(parserName .. " " .. parserVersion)
local parserDetails = [=[
Attempts to identify attempts against CVE-2020-0601.

Checks for proper ECC curve use after validating the TLS handshake
and that the session is using an ECC cryptography suite.

A notional alertID (nw999999) is sent if the traffic patterns match.
]=]

-- some of these locals are probably unnecessary
local dependencies = {
    ["parsers"] = {
        "FeedParser",
        "NETWORK",
        "nwll"
    },
    ["feeds"] = {
        "alertids_suspicious"
    }
}

local conflicts = {
    ["parsers"] = {
        "HTTPS",
        "TLSv1",
        "TLS-flex",
        "TLS_id"
    }
}

local keyUsage = {
    ["alert.id"]    = "mapped to risk meta"
}

local alertIDs = {
    ["suspicious"] = {
        ["nw999999"] = "CVE-2020-0601 attempt"
    }
}

local liveTags = {
    "operations",
    "event analysis",
    "protocol analysis",
}

--[[
    VERSION

        2020.01.18.1  dustin lee      11.4 ?         learning how to lua and borrowing from Bill's Parser book

    TODO

        - Test in various environments to vet detection and performance
        - Map to actual NW alertID
        - Learn more about information/context shared between sessions
        - Add ATT&CK and other context to alert
        - Include full ECC crypo suite comparison (e.g. full secp mapping: secp-384, full prime mapping, etc.)

    COMMENTS

        - All TLS 1.3 traffic inspected thus far has resulted in a handshake equal to one of the TLS versions in setCallbacks
--]]

local nwll=require("nwll")
--local debugParser = require('debugParser')

local indexKeys = {}
table.insert(indexKeys, nwlanguagekey.create("alert.id"))

tlsParser:setKeys(indexKeys)

local cipherSuites = ({
    [0xC001] = "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    [0xC002] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    [0xC003] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    [0xC004] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    [0xC005] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    [0xC006] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    [0xC007] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    [0xC008] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    [0xC009] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    [0xC00A] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    [0xC00B] = "TLS_ECDH_RSA_WITH_NULL_SHA",
    [0xC00C] = "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    [0xC00D] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    [0xC00E] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    [0xC00F] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    [0xC010] = "TLS_ECDHE_RSA_WITH_NULL_SHA",
    [0xC011] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    [0xC012] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    [0xC013] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    [0xC014] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    [0xC015] = "TLS_ECDH_anon_WITH_NULL_SHA",
    [0xC016] = "TLS_ECDH_anon_WITH_RC4_128_SHA",
    [0xC017] = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    [0xC018] = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    [0xC019] = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    [0xC023] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    [0xC024] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    [0xC025] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    [0xC026] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    [0xC027] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    [0xC028] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    [0xC029] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    [0xC02A] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    [0xC02B] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    [0xC02C] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    [0xC02D] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    [0xC02E] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    [0xC02F] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    [0xC030] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    [0xC031] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    [0xC032] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    [0xC033] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
    [0xC034] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
    [0xC035] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    [0xC036] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    [0xC037] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    [0xC038] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
    [0xC039] = "TLS_ECDHE_PSK_WITH_NULL_SHA",
    [0xC03A] = "TLS_ECDHE_PSK_WITH_NULL_SHA256",
    [0xC03B] = "TLS_ECDHE_PSK_WITH_NULL_SHA384",
    [0xC048] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
    [0xC049] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
    [0xC04A] = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
    [0xC04B] = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
    [0xC04C] = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
    [0xC04D] = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
    [0xC04E] = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
    [0xC04F] = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
    [0xC05C] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
    [0xC05D] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
    [0xC05E] = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
    [0xC05F] = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
    [0xC060] = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    [0xC061] = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    [0xC062] = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
    [0xC063] = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
    [0xC070] = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
    [0xC071] = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
    [0xC072] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    [0xC073] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    [0xC074] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    [0xC075] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    [0xC076] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    [0xC077] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    [0xC078] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    [0xC079] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    [0xC086] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    [0xC087] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    [0xC088] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    [0xC089] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    [0xC08A] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    [0xC08B] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    [0xC08C] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    [0xC08D] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    [0xC09A] = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    [0xC09B] = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    [0xC0AC] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    [0xC0AD] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    [0xC0AE] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    [0xC0AF] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
})

local eccSuites = ({
    [0x2B810400] = "SECP_SUITES",
    [0x2A8648CE] = "PRIME_SUITES",
    [0x2B240303] = "BRAINPOOL_SUITES"
})

local secpSuites = ({
    [0x21] = "SECP224",
    [0x22] = "SECP384",
    [0x23] = "SECP521"
})

local primeSuites = ({
    [0x3D030101] = "PRIME192",
    [0x3D030107] = "PRIME256"
})

function tlsParser:sessionBegin()
    -- reset session vars
    self.sessionVars = {
        --[[
            ["isECC"] 
        --]]
    }
end

function tlsParser:registerMeta(key, vlu)
    -- nw.logInfo("key: " .. key .. " and value: " .. vlu)
    nw.createMeta(key, vlu)
end

function tlsParser:tlsHandshake(token, first, last)
    local status, error = pcall(function(token, first, last)
        -- get a tiny payload object of just the next two bytes
        local payload = nw.getPayload(last + 1, last + 2)
        if payload then
            -- those two bytes are the length of the TLS section
            local payloadShort = nwpayload.uint16
            local tlsLength = payloadShort(payload, 1)
            if tlsLength then
                -- get a payload object of just the TLS section (in its entirety)
                payload = nw.getPayload(last + 3, last + 3 + tlsLength - 1)
                -- find a handshake type "certificate" (0x0b)
                local position = 1
                local payloadByte = nwpayload.uint8
                local handshakeType = payloadByte(payload, position)
                if handshakeType then
                    local loopCheck = 1
                    local loopCount = 0
                    while handshakeType == 2 and loopCheck == 1 and loopCount < 20 do
                        -- server hello - extract ciphersuite
                        loopCheck = 0
                        loopCount = loopCount + 1
                        local payloadByte, payloadShort = payloadByte, payloadShort
                        local position = position + 38 -- this "position" is local to this block, not the larger loop
                        local sessionIdLength = payloadByte(payload, position)
                        if sessionIdLength then
                            position = position + 1 + sessionIdLength
                            local cipherSuite = payloadShort(payload, position)
                            if cipherSuite then
                                if cipherSuites[cipherSuite] then
                                    self.sessionVars.isECC = true
                                end
                            end
                        end
                    end
                end
            end
        end
    end, token, first, last)
    if not status and debugParser then
        nw.logFailure(error)
    end
end

function tlsParser:eccCrypto(token, first, last)
    local status, error = pcall(function(token, first, last)
        local payload = nw.getPayload(last + 3, last + 7)
        if payload and payload:len() == 5 then
            if self.sessionVars.isECC and not eccSuites[payload:int32()] then
                self:registerMeta(self.keys["alert.id"], "nw999999")
                nw.logInfo("potential CVE-2020-0601 curveball attempt!")
            end
        end
    end, token, first, last)
    if not status and debugParser then
        nw.logFailure(error)
    end
end

tlsParser:setCallbacks({
    [nwevents.OnSessionBegin] = tlsParser.sessionBegin,
    ["\022\003\000"] = tlsParser.tlsHandshake,   -- SSL 3.0 0x160300
    ["\022\003\001"] = tlsParser.tlsHandshake,   -- TLS 1.0 0x160301
    ["\022\003\002"] = tlsParser.tlsHandshake,   -- TLS 1.1 0x160302
    ["\022\003\003"] = tlsParser.tlsHandshake,   -- TLS 1.2 0x160303
    ["\042\134\072\206\061\002\001"] = tlsParser.eccCrypto, -- ECC (id-ecPublicKey) 0x2a8648ce3d0201
})

return parserName, parserVersion, parserDetails, conflicts, dependencies, keyUsage, alertIDs, liveTags
