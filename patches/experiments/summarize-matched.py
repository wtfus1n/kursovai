#!/usr/bin/env python3
"""Verify and summarize the matched matrix; produce the report figures."""
import csv
from collections import defaultdict
import itertools
import json
from pathlib import Path
import statistics as st
import sys

RAW = Path(sys.argv[1])
FIG = Path(sys.argv[2])
TOPO = [("grid",0,"Решётка · 1 связь"),("grid",1,"Решётка · 2 связи"),
        ("triangle",0,"Треугольник"),("ring",0,"Кольцо")]
NODES = (25,50,100)
PROTOS = ("aodv","olsr")
ATTACKS = ("blackhole","grayhole","wormhole","sybil")
NAMES = dict(blackhole="Чёрная дыра",grayhole="Серая дыра",wormhole="Wormhole",sybil="Сивилла")
FIELDS = ("attack","topology","redundant","nodes","mode","control_plane_attack","probability",
          "tunnel_delay_ms","identities")
METRICS = ("cross_pdr","local_pdr","cross_delay_ms","local_delay_ms","cross_tunneled",
           "cross_route_hops","cross_routes","data_drops","control_drops","forged_replies",
           "sybil_announcements","fake_routes","false_gateways","tunnel_routing_frames",
           "tunnel_arp_frames","tunnel_data_frames","tunnel_replays")


def average(values):
    usable = [x for x in values if x is not None]
    return st.mean(usable) if usable else None


def describe(values):
    usable = [x for x in values if x is not None]
    if not usable:
        return None, 0, None
    return st.mean(usable),len(usable),2.262157*st.stdev(usable)/len(usable)**.5 if len(usable)==10 else None


def write_csv(path,rows):
    with path.open("w",encoding="utf-8-sig",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def params(r):
    return tuple(r[k] for k in FIELDS)


def summarize():
    records=[]
    traffic={}
    for protocol,attack in itertools.product(PROTOS,ATTACKS):
        path=RAW/f"{protocol}-{attack}.jsonl"
        seen=set()
        for line in path.read_text().splitlines():
            key,r=json.loads(line)
            assert key not in seen
            seen.add(key)
            assert (r["protocol"],r["attack"])==(protocol,attack)
            assert r["seed"]==49 and r["run"] in range(1,11)
            assert r["nodes"] in NODES and (r["topology"],r["redundant"]) in [(a,b) for a,b,_ in TOPO]
            assert len(r["flows"])==8
            streams=tuple((f["source"],f["destination"],f["start_s"],f["cross"]) for f in r["flows"])
            tkey=tuple(r[k] for k in ("topology","redundant","nodes","run"))
            assert traffic.setdefault(tkey,streams)==streams,(path,key)
            record={k:r[k] for k in (*FIELDS,"protocol","run","seed","attacker","peer")}
            for kind,cross in (("cross",True),("local",False)):
                flows=[f for f in r["flows"] if f["cross"]==cross]
                assert len(flows)==4 and all(f["sent"]==80 and 0<=f["received"]<=80 and
                    0<=f["tunneled_received"]<=f["received"] for f in flows),(path,key,flows)
                received=sum(f["received"] for f in flows)
                record[kind+"_pdr"]=100*received/320
                record[kind+"_delay_ms"]=sum(f["delay_sum_ms"] for f in flows)/received if received else None
                if cross:
                    record["cross_tunneled"]=sum(f["tunneled_received"] for f in flows)
                    hops=[f["final_hops"] for f in flows if f["final_hops"]]
                    record["cross_route_hops"]=average(hops)
                    record["cross_routes"]=len(hops)
            for k in METRICS[7:]:
                record[k]=r.get(k,0)
            if attack=="wormhole" and r["mode"] in ("off","control-only"):
                assert r["tunnel_data_frames"]==record["cross_tunneled"]==0
            records.append(record)
        assert len(seen)==dict(blackhole=360,grayhole=840,wormhole=840,sybil=480)[attack],(path,len(seen))
    assert len(records)==5040
    grouped=defaultdict(dict)
    for r in records:
        group=grouped[(r["protocol"],params(r))]
        assert r["run"] not in group
        group[r["run"]]=r
    assert len(grouped)==504
    off=lambda p:(p[0],p[1],p[2],p[3],"off",0,1 if p[0]=="blackhole" else .5,1,3)
    summary={}
    pairs=[]
    for (protocol,condition), values in grouped.items():
        assert set(values)==set(range(1,11))
        row=dict(zip(FIELDS,condition),protocol=protocol,repeats=10)
        for k in METRICS:
            row[k],row[k+"_n"],row[k+"_ci95"]=describe([r[k] for r in values.values()])
        control=grouped[(protocol,off(condition))]
        row["cross_delta"],_,row["cross_delta_ci95"]=describe(
            [values[i]["cross_pdr"]-control[i]["cross_pdr"] for i in range(1,11)])
        summary[protocol,condition]=row
        if protocol=="aodv":
            other=grouped["olsr",condition]
            other_control=grouped["olsr",off(condition)]
            d=[values[i]["cross_pdr"]-other[i]["cross_pdr"] for i in range(1,11)]
            e=[d[i-1]-(control[i]["cross_pdr"]-other_control[i]["cross_pdr"]) for i in range(1,11)]
            effect,_,effect_ci=describe(e)
            difference,_,difference_ci=describe(d)
            pairs.append(dict(zip(FIELDS,condition),pairs=10,aodv_minus_olsr_pp=difference,
                              ci95_halfwidth_pp=difference_ci,attack_effect_diff_pp=effect,
                              effect_ci95_halfwidth_pp=effect_ci))
    assert len(pairs)==252
    write_csv(RAW/"runs.csv",records)
    write_csv(RAW/"summary.csv",list(summary.values()))
    write_csv(RAW/"paired.csv",pairs)
    return summary


def variations(attack):
    yield ("Контр.", "off",0,1 if attack=="blackhole" else .5,1,3)
    if attack=="blackhole":
        yield ("Данные","attack",0,1,1,3)
        yield ("+ Служ.","attack",1,1,1,3)
    elif attack=="grayhole":
        for plane,p in itertools.product((0,1),(.25,.5,.75)):
            yield (str(p).replace(".",",")+("+" if plane else ""), "attack",plane,p,1,3)
    elif attack=="wormhole":
        for mode,delay in itertools.product(("control-only","control-and-data"),(1,10,50)):
            yield (("С" if mode=="control-only" else "С+Д")+str(delay),mode,0,.5,delay,3)
    else:
        for i in (1,3,10):
            yield (str(i),"attack",0,.5,1,i)


def draw(summary):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator
    plt.rcParams.update({"font.family":"DejaVu Sans","font.size":9,"axes.spines.top":False,
                         "axes.spines.right":False,"axes.labelcolor":"#333333"})
    FIG.mkdir(parents=True,exist_ok=True)
    for attack,metric,unit,file in [
        *((a,"cross_pdr","PDR, %",a) for a in ATTACKS),
        ("wormhole","cross_tunneled","UDP через туннель, шт.","wormhole-udp"),
        ("wormhole","false_gateways","Шлюзы без обычной связи, шт.","wormhole-gateways"),
        ("sybil","fake_routes","Фиктивные маршруты, шт.","sybil-routes"),
    ]:
        options=list(variations(attack))
        fig, axes=plt.subplots(3,4,figsize=(13.2,7.5),sharex=True,sharey=True)
        for i,nodes in enumerate(NODES):
            for j,(topology,redundant,title) in enumerate(TOPO):
                ax=axes[i][j]
                for p,sty,mark,shade in (("aodv","-","o","#171717"),("olsr","--","s","#686868")):
                    values=[summary[p,(attack,topology,redundant,nodes,*v[1:])][metric] for v in options]
                    ax.plot(range(len(options)),values,sty,marker=mark,color=shade,
                            linewidth=1.4,markersize=4,label=p.upper())
                ax.grid(axis="y",color="#ddd",linewidth=.5)
                if metric=="cross_pdr":
                    ax.set_ylim(-4,104)
                    ax.set_yticks([0,25,50,75,100])
                else:
                    ax.set_ylim(bottom=0)
                    ax.yaxis.set_major_locator(MaxNLocator(nbins=4,integer=True))
                ax.set_xticks(range(len(options)),[v[0] for v in options],fontsize=8)
                ax.set_xlim(-.2,len(options)-.8)
                if i==0:
                    ax.set_title(title,fontsize=11,fontweight="bold")
                if j==0:
                    ax.set_ylabel(f"{nodes} узлов\n{unit}",fontsize=10)
        handles,labels=axes[0][0].get_legend_handles_labels()
        fig.legend(handles,labels,loc="lower center",ncols=2,frameon=False,fontsize=11)
        fig.subplots_adjust(left=.078,right=.987,top=.937,bottom=.126,wspace=.15,hspace=.21)
        fig.savefig(FIG/(file+".png"),dpi=190,facecolor="white")
        plt.close(fig)

    fig,axs=plt.subplots(1,4,figsize=(13.2,3.25))
    for ax,(t,r,title) in zip(axs,TOPO):
        n=100
        if t=="grid":
            xy={i:((i%10)+(1.1 if i%10>=5 else 0),9-i//10) for i in range(n)}
            edges=[(i,j) for i in range(n) for j in (i+1,i+10) if j<n and
                   ((i+1==j and i//10==j//10 and i%10!=4) or (j==i+10))]
            edges += [(4,5)] + ([(94,95)] if r else [])
            endpoints=(54,55)
        else:
            import math
            count=3 if t=="triangle" else 4
            b=[i*n//count for i in range(count+1)]
            xy={}
            for g,(left,right) in enumerate(zip(b,b[1:])):
                angle=math.pi/2-g*math.tau/count
                center=(4.2*math.cos(angle),4.2*math.sin(angle))
                for j in range(left,right):
                    angle2=(j-left)*math.tau/(right-left)
                    xy[j]=(center[0]+1.7*math.cos(angle2),center[1]+1.7*math.sin(angle2))
            edges=[(i,i+1) for i in range(n-1)]+[(0,n-1)]+[(l,h-1) for l,h in zip(b,b[1:])]
            endpoints=((b[1]-b[0])//2,b[1]+(b[2]-b[1])//2)
        for u,v in edges:
            ax.plot((xy[u][0],xy[v][0]),(xy[u][1],xy[v][1]),color="#8a8a8a",lw=.65,zorder=1)
        ax.scatter([xy[i][0] for i in xy],[xy[i][1] for i in xy],s=4,color="#222",zorder=2)
        ax.plot([xy[i][0] for i in endpoints],[xy[i][1] for i in endpoints],":",color="#111",lw=1.4,zorder=3)
        ax.scatter([xy[i][0] for i in endpoints],[xy[i][1] for i in endpoints],s=24,
                   facecolor="white",edgecolor="black",zorder=4)
        ax.set_title(title,fontsize=11,fontweight="bold")
        ax.set_aspect("equal")
        ax.axis("off")
    fig.text(.5,.055,"Линии — обычные связи. Пунктир и белые метки — скрытый канал и его концы.",ha="center")
    fig.tight_layout(rect=(0,.1,1,1))
    fig.savefig(FIG/"topologies.png",dpi=190,facecolor="white")
    plt.close(fig)


if __name__=="__main__":
    data=summarize()
    draw(data)
    print(f"{len(data)} conditions verified and plotted.")

