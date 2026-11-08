// SPDX-License-Identifier: GPL-2.0-only
#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include <sstream>
#include <iostream>

using namespace ns3;
static uint32_t hidden = 0;
static uint32_t linkPackets = 0;
static void Hidden(uint8_t type, uint8_t oldHop, uint8_t newHop)
{
    NS_ABORT_MSG_IF(oldHop != newHop, "Tunnel must preserve received hop count");
    ++hidden;
}
static void LinkTx(Ptr<const Packet> p) { ++linkPackets; }
int main(int argc, char** argv)
{
    uint32_t mode = 2; // 0: disconnected, 1: ordinary private link, 2: hidden hop.
    CommandLine cmd;
    cmd.AddValue("mode", "0=disconnected, 1=ordinary link, 2=wormhole", mode);
    cmd.Parse(argc, argv);
    NS_ABORT_MSG_IF(mode > 2, "Invalid mode");
    RngSeedManager::SetSeed(49);
    RngSeedManager::SetRun(1);
    NodeContainer nodes;
    nodes.Create(4);
    AodvHelper aodv;
    aodv.Set("EnableHello", BooleanValue(false));
    aodv.Set("DestinationOnly", BooleanValue(true));
    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv);
    stack.Install(nodes);
    PointToPointHelper edge;
    edge.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    edge.SetChannelAttribute("Delay", StringValue("1ms"));
    NetDeviceContainer left = edge.Install(nodes.Get(0), nodes.Get(1));
    NetDeviceContainer right = edge.Install(nodes.Get(2), nodes.Get(3));
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    address.Assign(left);
    address.SetBase("10.1.2.0", "255.255.255.0");
    auto dst = address.Assign(right);
    if (mode > 0)
    {
        PointToPointHelper tunnel;
        tunnel.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
        tunnel.SetChannelAttribute("Delay", StringValue("100us"));
        auto devices = tunnel.Install(nodes.Get(1), nodes.Get(2));
        address.SetBase("10.1.3.0", "255.255.255.0");
        address.Assign(devices);
        for (uint32_t i = 0; i < 2; ++i)
        {
            auto node = nodes.Get(i + 1);
            auto rp = node->GetObject<aodv::RoutingProtocol>();
            uint32_t iface = node->GetObject<Ipv4>()->GetInterfaceForDevice(devices.Get(i));
            rp->SetAttribute("WormholeEnabled", BooleanValue(mode == 2));
            rp->SetAttribute("WormholeInterface", UintegerValue(iface));
            rp->TraceConnectWithoutContext("WormholeControl", MakeCallback(&Hidden));
            devices.Get(i)->TraceConnectWithoutContext("PhyTxBegin", MakeCallback(&LinkTx));
        }
    }
    aodv.AssignStreams(nodes, 100);
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 9000));
    auto sinkApps = sinkHelper.Install(nodes.Get(3));
    sinkApps.Start(Seconds(0));
    UdpClientHelper client(dst.GetAddress(1), 9000);
    client.SetAttribute("MaxPackets", UintegerValue(50));
    client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
    client.SetAttribute("PacketSize", UintegerValue(128));
    auto clientApps = client.Install(nodes.Get(0));
    clientApps.Start(Seconds(1));
    Simulator::Stop(Seconds(8));
    Simulator::Run();
    uint64_t received = DynamicCast<PacketSink>(sinkApps.Get(0))->GetTotalRx();
    std::ostringstream routing;
    nodes.Get(0)->GetObject<aodv::RoutingProtocol>()->PrintRoutingTable(Create<OutputStreamWrapper>(&routing));
    uint32_t advertisedHops = 0;
    std::istringstream lines(routing.str());
    std::string line;
    while (std::getline(lines, line))
    {
        std::istringstream fields(line);
        std::string destination, gateway, iface, state, expiry;
        uint32_t hops;
        if (fields >> destination >> gateway >> iface >> state >> expiry >> hops)
        {
            std::ostringstream expected;
            expected << dst.GetAddress(1);
            if (destination == expected.str() && state == "UP") advertisedHops = hops;
        }
    }
    std::cout << routing.str();
    std::cout << "RESULT mode=" << mode << " receivedBytes=" << received
              << " advertisedHops=" << advertisedHops << " hiddenControlHops=" << hidden << " tunnelLinkTx=" << linkPackets << std::endl;
    NS_ABORT_MSG_IF(mode == 0 && received != 0, "Disconnected baseline delivered packets");
    NS_ABORT_MSG_IF(mode > 0 && (received == 0 || linkPackets == 0), "Out-of-band link did not carry traffic");
    NS_ABORT_MSG_IF(mode == 1 && advertisedHops != 3, "Ordinary link must advertise three hops");
    NS_ABORT_MSG_IF(mode == 2 && advertisedHops != 2, "Tunnel must hide exactly one hop");
    NS_ABORT_MSG_IF(mode == 2 && hidden == 0, "Hidden hop was not exercised");
    NS_ABORT_MSG_IF(mode != 2 && hidden != 0, "Hidden hop must be off in baseline");
    Simulator::Destroy();
}
