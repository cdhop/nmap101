local sslcert = require 'sslcert'
local shortport = require "shortport"
local string = require 'string'
local stdnse = require 'stdnse'

description = [[Displays a TLS/SSL certificate's expiration date.]]

---
--@output
-- 443/tcp  open  https
-- |_ ssl-expire: 2016-11-17T12:59:00

categories = {"safe", "default"}
author = "hydroplane"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return stdnse.format_timestamp(date)
  end
end

action = function( host, port )
  local result
 
  local status, cert = sslcert.getCertificate(host, port)
  if status then
    local expiration_date = date_to_string(cert.validity.notAfter)
    result =  expiration_date
  else
    result = "Failed to get certificate"
  end
   
  return result
end
