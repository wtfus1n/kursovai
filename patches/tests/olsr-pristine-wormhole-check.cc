/* SPDX-License-Identifier: GPL-2.0-only */
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-module.h"
#include <iostream>

using namespace ns3;

static bool sawOriginal = false;
static bool sawReplay = false;

static void
ObserveHello(uint32_t endpoint, Ptr<const Packet> packet, Ptr<Ipv4>, uint32_t)
{
    auto copy = packet->Copy();
    Ipv4Header ip;
    UdpHeader udp;
    olsr::PacketHeader packetHeader;
    olsr::MessageHeader message;
    if (!copy->RemoveHeader(ip) || ip.GetProtocol() != 17 || !copy->RemoveHeader(udp) ||
        udp.GetDestinationPort() != 698 || !copy->RemoveHeader(packetHeader) ||
        !copy->RemoveHeader(message) || message.GetMessageType() != olsr::MessageHeader::HELLO_MESSAGE ||
        message.GetOriginatorAddress() != Ipv4Address("10.2.0.1"))
    {
        return;
    }
    NS_ABORT_MSG_IF(ip.GetSource() != Ipv4Address("10.1.0.2"),
                    "Replay must preserve the actual non-main IPv4 source");
    NS_ABORT_MSG_IF(Simulator::GetContext() != endpoint, "Replay ran in the wrong node context");
    if (endpoint == 1)
    {
        sawOriginal = true;
    }
    else
    {
        sawReplay = true;
    }
}

int main(int argc, char** argv)
{
    bool enabled = true;
    bool multiInterface = false;
    double probability = 0.5;
    uint32_t seed = 1;
    uint64_t run = 1;
    CommandLine cmd(__FILE__);
    cmd.AddValue("enabled", "Enable the attack on the designated physical node", enabled);
    cmd.AddValue("multiInterface", "Check wire source preservation with an excluded main interface", multiInterface);
    cmd.AddValue("probability", "Grayhole drop probability", probability);
    cmd.AddValue("seed", "RNG seed", seed);
    cmd.AddValue("run", "RNG run", run);
    cmd.Parse(argc, argv);
    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(run);
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));

    NodeContainer nodes;
    nodes.Create(4);
    NetDeviceContainer extra;
    if (multiInterface)
    {
        SimpleNetDeviceHelper excluded;
        extra = excluded.Install(nodes.Get(1));
    }
    auto channel = CreateObject<SimpleChannel>();
    channel->SetAttribute("Delay", TimeValue(MicroSeconds(10)));
    SimpleNetDeviceHelper simple;
    NetDeviceContainer devices = simple.Install(nodes, channel);
    for (uint32_t i = 0; i < 4; ++i)
    {
        for (uint32_t j = 0; j < 4; ++j)
        {
            if ((i < 2) != (j < 2))
            {
                channel->BlackList(DynamicCast<SimpleNetDevice>(devices.Get(i)),
                                   DynamicCast<SimpleNetDevice>(devices.Get(j)));
            }
        }
    }

    OlsrHelper olsr;
    olsr.Set("HelloInterval", TimeValue(Seconds(1)));
    olsr.Set("TcInterval", TimeValue(Seconds(2)));
    InternetStackHelper internet;
    internet.SetRoutingHelper(olsr);
    internet.Install(nodes);
    Ipv4AddressHelper address;
    if (multiInterface)
    {
        address.SetBase("10.2.0.0", "255.255.0.0");
        address.Assign(extra);
    }
    address.SetBase("10.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);
    std::vector<Ptr<olsr::RoutingProtocol>> protocols;
    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        protocols.push_back(nodes.Get(i)->GetObject<Ipv4>()->GetRoutingProtocol()->GetObject<olsr::RoutingProtocol>());
    }
    if (multiInterface)
    {
        protocols[1]->SetInterfaceExclusions({1});
        nodes.Get(1)->GetObject<Ipv4L3Protocol>()->TraceConnectWithoutContext(
            "Tx", MakeBoundCallback(&ObserveHello, 1u));
        nodes.Get(2)->GetObject<Ipv4L3Protocol>()->TraceConnectWithoutContext(
            "Tx", MakeBoundCallback(&ObserveHello, 2u));
    }
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
    uint32_t remote = 0;
    for (const auto& neighbor : protocols[0]->GetNeighbors())
    {
        if (neighbor.status == olsr::NeighborTuple::STATUS_SYM &&
            (neighbor.neighborMainAddr == interfaces.GetAddress(2) ||
             neighbor.neighborMainAddr == interfaces.GetAddress(3))) { ++remote; }
    }
    std::cout << "RESULT attack=wormhole enabled=" << enabled << " remoteNeighbors=" << remote
              << " routes=" << protocols[0]->GetRoutingTableEntries().size()
              << " transfers=" << uint64_t(0) + uint64_t(0)
              << " replays=" << uint64_t(0) + uint64_t(0) << std::endl;
    NS_ABORT_MSG_IF(enabled ? remote == 0 : remote != 0,
                    "Replay must create a false neighbor across disconnected radio components");
    if (multiInterface)
    {
        NS_ABORT_MSG_IF(!sawOriginal || sawReplay != enabled, "Unexpected wire observation");
        std::cout << "WIRE_CHECK original=" << sawOriginal << " replay=" << sawReplay << std::endl;
    }
    Simulator::Destroy();
    return 0;
}
