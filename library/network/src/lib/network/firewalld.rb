# encoding: utf-8
#
# ***************************************************************************
#
# Copyright (c) 2016 SUSE LLC.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 or 3 of the GNU General
# Public License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact SUSE LLC.
#
# To contact SUSE about this file by physical or electronic mail,
# you may find current contact information at www.suse.com
#
# ***************************************************************************
#
# File: lib/network/firewalld.rb
# Summary:  FirewallD configuration API
# Authors:  Karol Mroz <kmroz@suse.de>, Markos Chandras <mchandras@suse.de>
#

require "yast"

module Firewalld
  # exception when firewall-cmd fails
  class FirewallCMDError < StandardError
  end

  # Execute firewalld commands using firewall-cmd
  class FWCmd
    include Yast::Logger

    BASH_SCR_PATH = Yast::Path.new(".target.bash_output")
    # Base firewall-cmd command
    COMMAND = "LANG=C firewall-cmd"

    attr_reader :option_str

    def initialize(option_str)
      @option_str = option_str
    end

    def command
      "#{COMMAND} #{option_str}".strip.squeeze(" ")
    end

    # @param output [Boolean] Whether command output is desirable or not
    # @return [String] Firewalld command output
    # @return [Boolean] FIrewalld command exit code
    def fwd_result(output = true)
      cmd_result = Yast::SCR.Execute(BASH_SCR_PATH, command)

      # See firewall-cmd manpage for exit codes. Not all of them justify an
      # exception. 0 and 1 can be used as true and false respectively.
      case cmd_result["exit"]
      when 0, 1
        if output
          cmd_result["stdout"]
        else
          log.debug "#{command} returned: #{cmd_result["stdout"]}"
          cmd_result["exit"].zero? ? true : false
        end
      else
        raise FirewallCMDError, "Calling firewall-cmd (cmd: #{command}) failed: #{cmd_result["stderr"]}"
      end
    end
  end

  # The firewalld API. We only use the command line interface.
  class FirewalldAPI
    def self.create(type = :bash)
      case type
      when :bash
        FirewalldBashAPI.new
      when :dbus
        nil
      else
        raise "Unsupported Firewalld API type: #{type}"
      end
    end
  end

  # The firewalld bash API
  class FirewalldBashAPI
    include Yast::Logger

    # Simple wrapper for commands. Returns true on success
    def fwd_quiet_result(*args)
      fwcmd = FWCmd.new(args.join(""))
      fwcmd.fwd_result(false)
    end

    ### State ###

    # @return [Boolean] The firewalld service state (exit code)
    def running?
      fwd_quiet_result("--state")
    end

    # @return [Boolean] The firewalld reload result (exit code)
    def reload
      fwd_quiet_result("--reload")
    end

    # @return [Boolean] The firewalld complete-reload result (exit code)
    def complete_reload
      fwd_quiet_result("--complete-reload")
    end

    # @return [Boolean] The firewalld runtime-to-permanent result (exit code)
    def make_permanent
      fwd_quiet_result("--runtime-to-permanent")
    end

    ### Zones ####

    # @return [Array<String>] The firewalld zones
    def get_zones
      fwcmd = FWCmd.new("--permanent --get-zones")
      fwcmd.fwd_result.split(" ")
    end

    # @param zone [String] The firewall zone
    # @return [Array<String>] list of zone's interfaces
    def list_interfaces(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-interfaces")
      fwcmd.fwd_result.split(" ")
    end

    # @param zone [String] The firewall zone
    # @return [Arrray<String>] list of zone's services
    def list_services(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-services")
      fwcmd.fwd_result.split(" ")
    end

    # @param zone [String] The firewall zone
    # @return [Array<String>] list of zone's ports
    def list_ports(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-ports")
      fwcmd.fwd_result.split(" ")
    end

    # @param zone [String] The firewall zone
    # @return [Array<String>] list of zone's protocols
    def list_protocols(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-protocols")
      fwcmd.fwd_result.split(" ")
    end

    # @param zone [String] The firewall zone
    # @return [Array<String>] list of all information for given zone
    def list_all(zone)
      fwcmd = FWCmd.new("--permanent --zone=#{zone} --list-all")
      fwcmd.fwd_result.split("\n")
    end

    # @return [Array<String>] list of all information for all firewall zones
    def list_all_zones
      fwcmd = FWCmd.new("--permanent --list-all-zones")
      fwcmd.fwd_result.split("\n")
    end

    ### Interfaces ###

    # @param zone [String] The firewall zone
    # @param interface [String] The network interface
    # @return [Boolean] True if interface is assigned to zone
    def interface_enabled?(zone, interface)
      fwd_quiet_result("--permanent --zone=#{zone} --query-interface=#{interface}")
    end

    # @param zone [String] The firewall zone
    # @param interface [String] The network interface
    # @return [Boolean] True if interface was added to zone
    def add_interface(zone, interface)
      fwd_quiet_result("--permanent --zone=#{zone} --add-interface=#{interface}")
    end

    # @param zone [String] The firewall zone
    # @param interface [String] The network interface
    # @return [Boolean] True if interface was removed from zone
    def remove_interface(zone, interface)
      fwd_quiet_result("--permanent --zone=#{zone} --remove-interface=#{interface}")
    end

    ### Services ###

    # @return [Array<String>] list of firewall services
    def get_services
      fwcmd = FWCmd.new("--permanent --get-services")
      fwcmd.fwd_result.split(" ")
    end

    # @param service [String] The firewall service
    # @return [Array<String>] list of all information for the given service
    def info_service(service)
      fwcmd = FWCmd.new("--permanent --info-service #{service}")
      fwcmd.fwd_result.split("\n")
    end

    # @note --get-short and --get-description are not present in any firewalld
    # @note release at the moment so we expect exceptions and we treat them properly.
    # @note See: https://github.com/t-woerner/firewalld/pull/91
    # @param service [String] The firewall service
    # @return [String] Short description for service
    def get_service_short(service)
      # these may not exist on early firewalld releases
      fwcmd = FWCmd.new("--permanent --service=#{service} --get-short")
      fwcmd.fwd_result
    rescue FirewallCMDError
      log.warn "This firewalld version does not implement --service=<service> --get-short"
      service
    end

    # @note --get-short and --get-description are not present in any firewalld
    # @note release at the moment so we expect exceptions and we treat them properly.
    # @note See: https://github.com/t-woerner/firewalld/pull/91
    # @param service [String] the firewall service
    # @return [String] Description for service
    def get_service_description(service)
      fwcmd = FWCmd.new("--permanent --service=#{service} --get-description")
      fwcmd.fwd_result
    rescue FirewallCMDError
      log.warn "This firewalld version does not implement --service=<service> --get-description"
      service
    end

    # @param service [String] The firewall service
    # @return [Boolean] True if service definition exists
    def service_supported?(service)
      get_services.include?(service)
    end

    # @param zone [String] The firewall zone
    # @param service [String] The firewall service
    # @return [Boolean] True if service is enabled in zone
    def service_enabled?(zone, service)
      fwd_quiet_result("--permanent --zone=#{zone} --query-service=#{service}")
    end

    # @param service [String] The firewall service
    # @return [Array<String>] The firewall service ports
    def get_service_ports(service)
      fwcmd = FWCmd.new("--permanent --service=#{service} --get-ports")
      fwcmd.fwd_result.strip
    end

    # @param service [String] The firewall service
    # @return [Array<String>] The firewall service protocols
    def get_service_protocol(service)
      fwcmd = FWCmd.new("--permanent --service=#{service} --get-protocol")
      fwcmd.fwd_result.strip
    end

    # @param zone [String] The firewall zone
    # @param port [String] The firewall port
    # @return [Boolean] True if port is enabled in zone
    def port_enabled?(zone, port)
      fwd_quiet_result("--permanent --zone=#{zone} --query-port=#{port}")
    end

    # @param zone [String] The firewall zone
    # @param protocol [String] The zone protocol
    # @return [Boolean] True if protocol is enabled in zone
    def protocol_enabled?(zone, protocol)
      fwd_quiet_result("--permanent --zone=#{zone} --query-protocol=#{protocol}")
    end

    # @param zone [String] The firewall zone
    # @param service [String] The firewall service
    # @return [Boolean] True if service was added to zone
    def add_service(zone, service)
      fwd_quiet_result("--permanent --zone=#{zone} --add-service=#{service}")
    end

    # @param zone [String] The firewall zone
    # @param port [String] The firewall port
    # @return [Boolean] True if port was added to zone
    def add_port(zone, port)
      fwd_quiet_result("--permanent --zone=#{zone} --add-port=#{port}")
    end

    # @param zone [String] The firewall zone
    # @param protocol [String] The firewall protocol
    # @return [Boolean] True if protocol was added to zone
    def add_protocol(zone, protocol)
      fwd_quiet_result("--permanent --zone=#{zone} --add-protocol=#{protocol}")
    end

    # @param zone [String] The firewall zone
    # @param service [String] The firewall service
    # @return [Boolean] True if service was removed from zone
    def remove_service(zone, service)
      fwd_quiet_result("--permanent --zone=#{zone} --remove-service=#{service}")
    end

    # @param zone [String] The firewall zone
    # @param port [String] The firewall port
    # @return [Boolean] True if port was removed from zone
    def remove_port(zone, port)
      fwd_quiet_result("--permanent --zone=#{zone} --remove-port=#{port}")
    end

    # @param zone [String] The firewall zone
    # @param protocol [String] The firewall protocol
    # @return [Boolean] True if protocol was removed from zone
    def remove_protocol(zone, protocol)
      fwd_quiet_result("--permanent --zone=#{zone} --remove-protocol=#{protocol}")
    end

    # @param zone [String] The firewall zone
    # @return [Boolean] True if masquerade is enabled in zone
    def masquerade_enabled?(zone)
      fwd_quiet_result("--permanent --zone=#{zone} --query-masquerade")
    end

    # @param zone [String] The firewall zone
    # @return [Boolean] True if masquerade was enabled in zone
    def add_masquerade(zone)
      return true if masquerade_enabled?(zone)
      fwd_quiet_result("--permanent --zone=#{zone} --add-masquerade")
    end

    # @param zone [String] The firewall zone
    # @return [Boolean] True if masquerade was removed in zone
    def remove_masquerade(zone)
      return true if !masquerade_enabled?(zone)
      fwd_quiet_result("--permanent --zone=#{zone} --remove-masquerade")
    end

    ### Logging ###

    # @param kind [String] Denied packets to log. Possible values are:
    # all, unicast, broadcast, multicast and off
    # @return [Boolean] True if desired packet type is being logged when denied
    def log_denied_packets?(kind)
      fwcmd = FWCmd.new("--get-log-denied")
      fwcmd.fwd_result.strip == value ? true : false
    end

    # @param kind [String] Denied packets to log. Possible values are:
    # all, unicast, broadcast, multicast and off
    # @return [Boolean] True if desired packet type was set to being logged
    # when denied
    def log_denied_packets=(kind)
      fwd_quiet_result("--set-log-denied=#{kind}")
    end

    # @return [String] packet type which is being logged when denied
    def log_denied_packets
      fwcmd = FWCmd.new("--get-log-denied")
      fwcmd.fwd_result.strip
    end
  end
end
