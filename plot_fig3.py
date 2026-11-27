import csv, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
rows=[r for r in csv.DictReader(open('results/results_e4.csv'))]
def series(t): return [(int(r['input_chars'])/1024, float(r['time_ms'])) for r in rows if r['test']==t]
u=series('unbounded_email'); b=series('template_email_bounded')
plt.rcParams.update({"font.family":"serif","font.serif":["Liberation Serif","Times New Roman","DejaVu Serif"],"font.size":9})
fig,ax=plt.subplots(figsize=(3.4,2.35),dpi=300)
ux=[x for x,y in u if y>=0]; uy=[y for x,y in u if y>=0]
ax.plot(ux,uy,color="#f47230",lw=2,marker="s",ms=4,zorder=3)
to=[x for x,y in u if y<0]
if to: ax.plot(to,[60000]*len(to),ls="none",marker="^",ms=6,color="#f47230",zorder=3); ax.annotate(">60 s (aborted)",(to[0],60000),xytext=(4,7),textcoords="offset points",ha="right",va="bottom",fontsize=7.5,color="#333333")
ax.plot([x for x,_ in b],[y for _,y in b],color="#257de0",lw=2,marker="o",ms=4,zorder=3)
ax.set_xscale("log",base=2); ax.set_yscale("log"); ax.set_ylim(0.1,3e5)
ax.set_xticks([4,8,16,32,64]); ax.set_xticklabels(["4","8","16","32","64"])
ax.set_xlabel("Input size (KiB, no '@' present)"); ax.set_ylabel("Matching time (ms, log scale)")
ax.text(4.1,2.0e4,"Unbounded email pattern",color="#333333",fontsize=7.5,ha="left",va="bottom")
ax.text(4.1,3.0,"Bounded template pattern",color="#333333",fontsize=7.5,ha="left",va="bottom")
ax.grid(True,which="major",color="#e6e6e6",lw=0.6); ax.set_axisbelow(True)
for s in ["top","right"]: ax.spines[s].set_visible(False)
for s in ["left","bottom"]: ax.spines[s].set_color("#9c9c9c")
ax.tick_params(colors="#555555",labelsize=8)
fig.tight_layout(); fig.savefig("fig3.png",dpi=300)
