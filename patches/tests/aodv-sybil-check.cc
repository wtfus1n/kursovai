// SPDX-License-Identifier: GPL-2.0-only
#include "ns3/aodv-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include <iostream>
#include <sstream>
using namespace ns3;
static uint32_t sent = 0;
static void
IdentityTx(bool disableAfterFirst, aodv::RoutingProtocol* attacker, Ipv4Address)
{
    ++sent;
    if (disableAfterFirst && sent == 1)
    {
        attacker->SetAttribute("SybilEnabled", BooleanValue(false));
        // Let all remaining sends in this batch run before the first received entry expires.
        Simulator::Stop(MilliSeconds(300));
    }
}
int main(int argc, char** argv)
{
    bool attack = true;
    bool disableAfterFirst = false;
    uint32_t count = 3;
    CommandLine cmd;
    cmd.AddValue("attack", "Enable fake HELLO identities", attack);
    cmd.AddValue("count", "Number of fake identities", count);
    cmd.AddValue("disableAfterFirst", "Disable Sybil after the first accepted socket send", disableAfterFirst);
    cmd.Parse(argc, argv);
    NS_ABORT_MSG_IF(count < 1 || count > 256, "count must be 1..256");
    NS_ABORT_MSG_IF(disableAfterFirst && (!attack || count < 2),
                    "disableAfterFirst requires an enabled attack and at least two identities");
    RngSeedManager::SetSeed(49);
    RngSeedManager::SetRun(1);
    NodeContainer nodes;
    nodes.Create(2);
    AodvHelper aodv;
    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv);
    stack.Install(nodes);
    PointToPointHelper link;
    link.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    link.SetChannelAttribute("Delay", StringValue("1ms"));
    auto devices = link.Install(nodes);
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    address.Assign(devices);
    auto attacker = nodes.Get(0)->GetObject<aodv::RoutingProtocol>();
    attacker->SetAttribute("SybilEnabled", BooleanValue(attack));
    attacker->SetAttribute("SybilIdentityCount", UintegerValue(count));
    attacker->TraceConnectWithoutContext(
        "SybilIdentityTx", MakeBoundCallback(&IdentityTx, disableAfterFirst, PeekPointer(attacker)));
    aodv.AssignStreams(nodes, 100);
    Simulator::Stop(Seconds(4));
    Simulator::Run();
    std::ostringstream routing;
    nodes.Get(1)->GetObject<aodv::RoutingProtocol>()->PrintRoutingTable(Create<OutputStreamWrapper>(&routing));
    uint32_t accepted = 0;
    for (uint32_t i = 0; i < count; ++i)
    {
        std::ostringstream identity;
        identity << Ipv4Address(Ipv4Address("10.250.0.1").Get() + i);
        std::istringstream lines(routing.str());
        std::string line;
        while (std::getline(lines, line))
        {
            std::istringstream fields(line);
            std::string destination, gateway, iface, state;
            if ((fields >> destination >> gateway >> iface >> state) &&
                destination == identity.str() && state == "UP")
            {
                ++accepted;
                break;
            }
        }
    }
    std::cout << routing.str();
    std::cout << "RESULT attack=" << attack << " requestedIdentities=" << count
              << " transmittedIdentities=" << sent << " acceptedIdentities=" << accepted << std::endl;
    if (disableAfterFirst)
    {
        NS_ABORT_MSG_IF(sent != 1 || accepted != 1, "Pending sends escaped the disabled attack");
    }
    else
    {
        NS_ABORT_MSG_IF(attack && (accepted != count || sent < count),
                        "Observer did not accept each fake identity");
    }
    NS_ABORT_MSG_IF(!attack && (accepted != 0 || sent != 0), "Fake identities leaked into baseline");
    Simulator::Destroy();
}
