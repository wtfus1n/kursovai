/* SPDX-License-Identifier: GPL-2.0-only */
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-module.h"
#include <iostream>

using namespace ns3;

static uint64_t observedFakePackets = 0;

static void
ObserveFakePacket(uint32_t first, uint32_t last, Ptr<const Packet> packet, Ptr<Ipv4>, uint32_t)
{
    auto copy = packet->Copy();
    Ipv4Header ip;
    UdpHeader udp;
    if (copy->RemoveHeader(ip) && ip.GetProtocol() == 17 && ip.GetSource().Get() >= first &&
        ip.GetSource().Get() <= last && copy->RemoveHeader(udp) && udp.GetDestinationPort() == 698)
    {
        ++observedFakePackets;
    }
}

int main(int argc, char** argv)
{
    bool enabled = true;
    bool checksums = true;
    bool twoInterfaces = false;
    uint32_t identities = 3;
    std::string fakeBase = "10.1.200.1";
    double probability = 0.5;
    uint32_t seed = 1;
    uint64_t run = 1;
    CommandLine cmd(__FILE__);
    cmd.AddValue("enabled", "Enable the attack on the designated physical node", enabled);
    cmd.AddValue("identities", "Number of simulated fake identities", identities);
    cmd.AddValue("base", "First reserved fake IPv4 address", fakeBase);
    cmd.AddValue("checksums", "Enable IPv4 and UDP checksums", checksums);
    cmd.AddValue("twoInterfaces", "Use an additional isolated interface on the attacker", twoInterfaces);
    cmd.AddValue("probability", "Grayhole drop probability", probability);
    cmd.AddValue("seed", "RNG seed", seed);
    cmd.AddValue("run", "RNG run", run);
    cmd.Parse(argc, argv);
    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(run);
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(checksums));

    NodeContainer nodes;
    nodes.Create(2);
    auto channel = CreateObject<SimpleChannel>();
    channel->SetAttribute("Delay", TimeValue(MicroSeconds(10)));
    SimpleNetDeviceHelper simple;
    NetDeviceContainer devices = simple.Install(nodes, channel);
    NetDeviceContainer extra;
    if (twoInterfaces)
    {
        extra = simple.Install(nodes.Get(1));
    }


    OlsrHelper olsr;
    olsr.Set("HelloInterval", TimeValue(Seconds(1)));
    olsr.Set("TcInterval", TimeValue(Seconds(2)));
    InternetStackHelper internet;
    internet.SetRoutingHelper(olsr);
    internet.Install(nodes);
    Ipv4AddressHelper address;
    address.SetBase("10.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);
    if (twoInterfaces)
    {
        address.SetBase("10.2.0.0", "255.255.0.0");
        address.Assign(extra);
    }
    std::vector<Ptr<olsr::RoutingProtocol>> protocols;
    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        protocols.push_back(nodes.Get(i)->GetObject<Ipv4>()->GetRoutingProtocol()->GetObject<olsr::RoutingProtocol>());
    }
    protocols[1]->SetAttribute("SybilEnabled", BooleanValue(enabled));
    protocols[1]->SetAttribute("SybilCount", UintegerValue(identities));
    Ipv4Address fakeStart(fakeBase.c_str());
    protocols[1]->SetAttribute("SybilAddressBase", Ipv4AddressValue(fakeStart));
    uint32_t first = fakeStart.Get();
    uint32_t last = first + identities - 1;
    nodes.Get(1)->GetObject<Ipv4L3Protocol>()->TraceConnectWithoutContext(
        "Tx", MakeBoundCallback(&ObserveFakePacket, first, last));
    olsr.AssignStreams(nodes, 100);


    Simulator::Stop(Seconds(55));
    Simulator::Run();
    uint64_t routeFingerprint = 1469598103934665603ULL;
    for (const auto& protocol : protocols)
    {
        for (const auto& route : protocol->GetRoutingTableEntries())
        {
            routeFingerprint = (routeFingerprint ^ route.destAddr.Get()) * 1099511628211ULL;
            routeFingerprint = (routeFingerprint ^ route.nextAddr.Get()) * 1099511628211ULL;
            routeFingerprint = (routeFingerprint ^ route.distance) * 1099511628211ULL;
        }
    }
    std::cout << "STATE routeFingerprint=" << routeFingerprint << std::endl;
    uint32_t fake = 0;
    for (const auto& neighbor : protocols[0]->GetNeighbors())
    {
        if (neighbor.status == olsr::NeighborTuple::STATUS_SYM &&
            neighbor.neighborMainAddr.Get() >= first && neighbor.neighborMainAddr.Get() <= last)
        {
            ++fake;
        }
    }
    std::cout << "RESULT attack=sybil enabled=" << enabled << " fakeNeighbors=" << fake
              << " totalNeighbors=" << protocols[0]->GetNeighbors().size()
              << " topology=" << protocols[0]->GetTopologySet().size()
              << " emitted=" << protocols[1]->GetSybilPackets() << std::endl;
    NS_ABORT_MSG_IF(fake != (enabled ? identities : 0), "Fake identities were not accepted as expected");
    NS_ABORT_MSG_IF(protocols[0]->GetTopologySet().size() != (enabled ? identities : 0),
                    "Each fake identity must create one topology entry");
    NS_ABORT_MSG_IF(protocols[1]->GetSybilPackets() != observedFakePackets,
                    "Sybil counter must match IPv4 sends across all interfaces");
    Simulator::Destroy();
    return 0;
}
