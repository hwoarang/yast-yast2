#!/usr/bin/env rspec

require_relative "test_helper"

Yast.import "SuSEFirewallServices"
Yast.import "SCR"
Yast.import "FileUtils"

# Make sure we have the right class.
if Yast::SuSEFirewallServicesClass.class != Yast::SuSEFirewalldServicesClass
  Yast::SuSEFirewallServices.morph_to(:fwd)
end

describe Yast::SuSEFirewallServices do
  context "given a running FirewallD instance" do
    it "can read all the installed firewall services" do
      services_on_disk = []
      Yast::SuSEFirewalldServicesClass::SERVICES_DIR.each do |dir|
        next if !Yast::FileUtils.Exists(dir)
        Dir.entries(dir).each do |s|
          next if Yast::SuSEFirewalldServicesClass::IGNORED_SERVICES.include?(s)
          services_on_disk << s.partition(".xml")[0]
        end
      end
      services_on_disk.uniq!
      expect(subject.all_services.keys.sort).to eq(services_on_disk.sort)
      expect(subject.GetSupportedServices.keys.sort).to eq(services_on_disk.sort)
    end

    it "can read the TCP ports of the SSH service" do
      expect(subject.GetNeededTCPPorts("ssh")).to eq(["22"])
    end

    it "returns an empty array of UDP ports for the SSH service" do
      expect(subject.GetNeededUDPPorts("ssh")).to eq([])
    end

    it "accepts old style SF2 service definitions as service input" do
      expect(subject.GetNeededTCPPorts("service:ssh")).to eq(["22"])
    end

    it "knows that no-service is not a valid service" do
      expect(subject.IsKnownService("no-service")).to be false
    end

    it "can get all the service and ports information from a service" do
      expect(subject.GetNeededPortsAndProtocols("ipsec")).to include("ip_protocols" => ["ah", "esp"])
    end

  end
end
