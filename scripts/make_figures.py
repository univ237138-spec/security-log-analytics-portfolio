"""Generate original charts from verified public demo outputs (portable fonts)."""
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch

from common import ROOT, read_rows

OUT = ROOT / 'assets'
OUT.mkdir(exist_ok=True)
NAVY, BLUE, TEAL, GRAY = '#10243e', '#2476d2', '#129a91', '#65768b'
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':12,'axes.spines.top':False,
                     'axes.spines.right':False,'axes.labelcolor':NAVY,'text.color':NAVY,
                     'figure.facecolor':'white','axes.titleweight':'bold','savefig.facecolor':'white'})

rows = read_rows(ROOT / 'data/13_baseline_variants/summary.csv')
fig, ax = plt.subplots(figsize=(10.5,5.6),layout='constrained')
labels = ['V0  Personal / peer','V1  Personal / global','V2  Global start time']
counts = [int(r['normal_sessions_flagged']) for r in rows]
bars = ax.barh(labels,counts,color=[BLUE,TEAL,'#9db4ce'],height=.52)
ax.invert_yaxis()
ax.set_xlim(0,9)
ax.set_xticks(range(0,10))
ax.set_xlabel('Sessions flagged among assumed-normal sessions')
fig.suptitle('Fewer false-positive candidates with a simpler fallback',fontsize=17,weight='bold')
ax.set_title('4 scenario alert sessions retained in every variant',loc='left',pad=14,fontsize=11,color=GRAY)
ax.grid(axis='x',alpha=.12)
ax.set_axisbelow(True)
for bar, count in zip(bars,counts):
    ax.text(count+.16,bar.get_y()+bar.get_height()/2,str(count),va='center',fontsize=20,weight='bold')
fig.savefig(OUT / 'baseline-comparison.png',dpi=160)
plt.close(fig)

sessions = read_rows(ROOT / 'data/07_sessions/sessions.csv')
excluded = {'S122','S132','S137','S142'}
persons = sorted({s['person_candidate'] for s in sessions})
from datetime import datetime,timedelta
hours = [[(datetime.fromisoformat(s['start_utc'])+timedelta(hours=9)).hour+
          (datetime.fromisoformat(s['start_utc'])+timedelta(hours=9)).minute/60
          for s in sessions if s['person_candidate']==p and s['work_session_id'] not in excluded] for p in persons]
fig,ax = plt.subplots(figsize=(10.5,6),layout='constrained')
ax.boxplot(hours,tick_labels=persons,orientation='horizontal',patch_artist=True,
           boxprops={'facecolor':'#dceafa','edgecolor':BLUE},medianprops={'color':TEAL,'linewidth':2})
ax.set_xlim(7,21)
ax.set_xticks(range(8,21,2),[f'{h:02d}:00' for h in range(8,21,2)])
ax.set_xlabel('Session start time (KST)')
ax.set_title('Personal schedules differ, but overlap substantially',loc='left',pad=20,fontsize=17)
ax.grid(axis='x',alpha=.12)
fig.savefig(OUT/'start-time-distribution.png',dpi=160)
plt.close(fig)

risk = read_rows(ROOT/'data/10_risk/session_risk.csv')
values = sorted([float(s['risk_score']) for s in risk],reverse=True)
fig,ax = plt.subplots(figsize=(10.5,5.6),layout='constrained')
ax.scatter(np.arange(1,len(values)+1),values,s=28,color=[TEAL if v>=100 else BLUE for v in values])
ax.axhline(100,color='#cc6853',linestyle='--',label='Score threshold = 100; tactic criterion also applies')
ax.set_xlabel('Session rank by risk score (146 sessions)')
ax.set_ylabel('Risk score (points, not a probability)')
ax.set_title('Multiple signals create an investigation priority',loc='left',pad=18,fontsize=18)
ax.grid(axis='y',alpha=.12)
ax.legend(loc='upper right',frameon=False,fontsize=10)
fig.savefig(OUT/'risk-distribution.png',dpi=160)
plt.close(fig)

fig = plt.figure(figsize=(12.8,6.4),dpi=100,facecolor=NAVY)
fig.text(.06,.83,'SECURITY LOG ANALYTICS',color='white',fontsize=31,weight='bold')
fig.text(.06,.75,'From heterogeneous logs to explainable investigation priorities',color='#b7cde7',fontsize=15)
items = [('9,125','log events'),('146','work sessions'),('3','baseline variants'),('4','alert sessions')]
for i,(value,label) in enumerate(items):
    x=.06+i*.235
    fig.patches.append(FancyBboxPatch((x,.34),.20,.27,boxstyle='round,pad=0.012',
                                    transform=fig.transFigure,facecolor='#1e3c60',edgecolor='#385b83'))
    fig.text(x+.018,.475,value,color='white',fontsize=37,weight='bold')
    fig.text(x+.018,.385,label,color='#b7cde7',fontsize=13)
fig.text(.06,.21,'DATA QUALITY  /  STATISTICS  /  BASELINE COMPARISON  /  DASHBOARD',color='#64d1c5',fontsize=13,weight='bold')
fig.text(.06,.10,'Hyunsoo Kim  |  Personal data analysis portfolio  |  Public demo data',color='#a7bfd9',fontsize=12)
fig.savefig(OUT/'social-preview.png',dpi=100,facecolor=NAVY)
plt.close(fig)
print('Generated: baseline comparison, start-time distribution, risk distribution, social preview.')
