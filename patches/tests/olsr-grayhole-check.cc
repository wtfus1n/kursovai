/* SPDX-License-Identifier: GPL-2.0-only */
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-module.h"
#include <iostream>

using namespace ns3;

int main(int argc, char** argv)
{
    bool enabled = true;
    double probability = 0.5;
    uint32_t seed = 1;
    uint64_t run = 1;
    CommandLine cmd(__FILE__);
    cmd.AddValue("enabled", "Enable the attack on the designated physical node", enabled);
    cmd.AddValue("probability", "Grayhole drop probability", probability);
    cmd.AddValue("seed", "RNG seed", seed);
    cmd.AddValue("run", "RNG run", run);
    cmd.Parse(argc, argv);
    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(run);
    RngSeedManager::ResetNextStreamIndex();
    {
        auto routing = CreateObject<olsr::RoutingProtocol>();
        auto downstream = CreateObject<UniformRandomVariable>();
        NS_ABORT_MSG_IF(RngSeedManager::GetNextStreamIndex() != 2,
                        "Disabled grayhole changed the automatic RNG stream allocation");
    }
    RngSeedManager::ResetNextStreamIndex();
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));

    NodeContainer nodes;
    nodes.Create(5);
    auto channel = CreateObject<SimpleChannel>();
    channel->SetAttribute("Delay", TimeValue(MicroSeconds(10)));
    SimpleNetDeviceHelper simple;
    NetDeviceContainer devices = simple.Install(nodes, channel);
    for (uint32_t i = 0; i < 5; ++i)
    {
        for (uint32_t j = 0; j < 5; ++j)
        {
            if (i != j && (i > j ? i - j : j - i) != 1)
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
    address.SetBase("10.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);
    std::vector<Ptr<olsr::RoutingProtocol>> protocols;
    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        protocols.push_back(nodes.Get(i)->GetObject<Ipv4>()->GetRoutingProtocol()->GetObject<olsr::RoutingProtocol>());
    }
    protocols[2]->SetAttribute("AttackEnabled", BooleanValue(enabled));
    protocols[2]->SetAttribute("AttackStart", TimeValue(Seconds(30)));
    protocols[2]->SetAttribute("AttackDropProbability", DoubleValue(probability));
    olsr.AssignStreams(nodes, 100);

    PacketSinkHelper sink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 9000));
    auto sinks = sink.Install(nodes.Get(4));
    sinks.Start(Seconds(0));
    PacketSinkHelper localSink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 9001));
    auto localSinks = localSink.Install(nodes.Get(2));
    localSinks.Start(Seconds(0));
    UdpClientHelper client(interfaces.GetAddress(4), 9000);
    client.SetAttribute("MaxPackets", UintegerValue(300));
    client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
    client.SetAttribute("PacketSize", UintegerValue(128));
    auto source = client.Install(nodes.Get(0));
    source.Start(Seconds(20));
    source.Stop(Seconds(50));
    UdpClientHelper localClient(interfaces.GetAddress(2), 9001);
    localClient.SetAttribute("MaxPackets", UintegerValue(300));
    localClient.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
    localClient.SetAttribute("PacketSize", UintegerValue(128));
    auto localSource = localClient.Install(nodes.Get(0));
    localSource.Start(Seconds(20));
    localSource.Stop(Seconds(50));
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
    auto delivered = DynamicCast<PacketSink>(sinks.Get(0))->GetTotalRx() / 128;
    auto local = DynamicCast<PacketSink>(localSinks.Get(0))->GetTotalRx() / 128;
    std::cout << "RESULT attack=grayhole enabled=" << enabled << " probability=" << probability
              << " delivered=" << delivered << " local=" << local
              << " dataDrops=" << protocols[2]->GetAttackDataDrops()
              << " controlDrops=" << protocols[2]->GetAttackControlDrops() << std::endl;
    NS_ABORT_MSG_IF(local < 250, "Locally addressed traffic must survive the forwarding attack");
    if (!enabled || probability == 0)
    {
        NS_ABORT_MSG_IF(delivered < 250 || protocols[2]->GetAttackDataDrops() != 0,
                        "Disabled/zero-probability attack must preserve delivery");
    }
    else
    {
        NS_ABORT_MSG_IF(protocols[2]->GetAttackDataDrops() == 0, "No actual transit packets dropped");
        NS_ABORT_MSG_IF(protocols[2]->GetAttackControlDrops() == 0, "No eligible MPR messages dropped");
        NS_ABORT_MSG_IF(delivered >= 290, "Attack had no observed delivery effect");
    }
    Simulator::Destroy();
    return 0;
}
