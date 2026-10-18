"""Independent frozen semantic oracle for SPEC.md v1; no agent implementation imported here."""
from decimal import Decimal, ROUND_HALF_UP
from datetime import date, timedelta
from collections import Counter, defaultdict
import argparse, hashlib, importlib.util, json, pathlib, random
SPEC_SHA='46d01d465de5271b977b7c6c1e8c617564053a660672df991be5b6dcf57cba1f'
ZERO=Decimal(0)
def number(x): return Decimal(str(x or 0))
def money(x):
    v=float(x.quantize(Decimal('0.01'),rounding=ROUND_HALF_UP))
    return 0.0 if v==0 else v
def label(r,k,default=''):
    v=r.get(k)
    return default if v is None or not str(v).strip() else str(v).strip()
def day(r):
    s=r.get('date')
    if not isinstance(s,str): return None
    try:
        d=date.fromisoformat(s)
        return d if d.isoformat()==s else None
    except ValueError: return None
FEATURES={
'A1':'cash_flow','A2':'amount_stats','A3':'largest_expenses','A4':'spend_bands','A5':'reimbursement','A6':'recurring','A7':'merchant_totals','A8':'payment_methods',
'B1':'by_category','B2':'category_stats','B3':'category_leader','B4':'category_shares','B5':'budgets','B6':'currency_totals','B7':'currency_category','B8':'uncategorized',
'C1':'date_range','C2':'by_month','C3':'by_day','C4':'monthly_flow','C5':'activity','C6':'weekend','C7':'daily_average','C8':'longest_streak',
'D1':'taxes','D2':'deductible','D3':'receipts','D4':'duplicate_ids','D5':'data_quality','D6':'refund_links','D7':'review_flags','D8':'split_allocations'}
def expected(rows,budgets=None):
    amounts=[number(r.get('amount')) for r in rows]
    def total(ix): return sum((amounts[i] for i in ix),ZERO)
    def flow(ix):
        a=[amounts[i] for i in ix]
        return {'spending':money(sum((x for x in a if x>0),ZERO)), 'refunds':money(-sum((x for x in a if x<0),ZERO)), 'net':money(sum(a,ZERO))}
    out={'count':len(rows),'total':money(sum(amounts,ZERO)),'cash_flow':flow(range(len(rows)))}
    ranked=sorted(amounts); n=len(ranked)
    out['amount_stats']={k:money(v) for k,v in (dict(min=ranked[0],max=ranked[-1],mean=sum(ranked,ZERO)/n,median=ranked[n//2] if n%2 else (ranked[n//2-1]+ranked[n//2])/2) if n else dict.fromkeys(['min','max','mean','median'],ZERO)).items()}
    out['largest_expenses']=[{'index':i,'amount':money(amounts[i]),'merchant':label(rows[i],'merchant','unknown')} for i in sorted((i for i,a in enumerate(amounts) if a>0),key=lambda i:(-amounts[i],i))[:3]]
    out['spend_bands']=dict.fromkeys(['refund','zero','small','medium','large'],0)
    for a in amounts: out['spend_bands']['refund' if a<0 else 'zero' if a==0 else 'small' if a<10 else 'medium' if a<100 else 'large']+=1
    eligible=[i for i,r in enumerate(rows) if amounts[i]>0 and r.get('reimbursable') is True]; paid=[i for i in eligible if rows[i].get('reimbursed') is True]
    out['reimbursement']={'eligible':money(total(eligible)),'paid':money(total(paid)),'outstanding':money(total(eligible)-total(paid))}
    recurring=[i for i,r in enumerate(rows) if r.get('recurring') is True];out['recurring']={'count':len(recurring),'total':money(total(recurring))}
    groups={}
    for field,default in [('merchant','unknown'),('payment_method','unknown'),('category','uncategorized'),('currency','USD')]:
        g=defaultdict(list)
        for i,r in enumerate(rows):g[label(r,field,default)].append(i)
        groups[field]=dict(sorted(g.items()))
    out['merchant_totals']={k:money(total(v)) for k,v in groups['merchant'].items()}
    out['payment_methods']={k:{'count':len(v),'total':money(total(v))} for k,v in groups['payment_method'].items()}
    out['by_category']={k:money(total(v)) for k,v in groups['category'].items()}
    out['category_stats']={k:{'count':len(v),**flow(v)} for k,v in groups['category'].items()}
    positive={k:sum((amounts[i] for i in v if amounts[i]>0),ZERO) for k,v in groups['category'].items()};gross=sum(positive.values(),ZERO)
    out['category_leader']=min((k for k in positive if positive[k]>0),key=lambda k:(-positive[k],k),default=None)
    out['category_shares']={k:money(v*100/gross) if gross else 0.0 for k,v in positive.items()}
    out['budgets']={k:{'budget':money(number(v)),'spent':money(positive.get(k,ZERO)),'remaining':money(number(v)-positive.get(k,ZERO)),'over':money(max(positive.get(k,ZERO)-number(v),ZERO))} for k,v in sorted((budgets or {}).items())}
    out['currency_totals']={k:money(total(v)) for k,v in groups['currency'].items()}
    out['currency_category']={}
    for curr,ix in groups['currency'].items():
        cats=defaultdict(list)
        for i in ix:cats[label(rows[i],'category','uncategorized')].append(i)
        out['currency_category'][curr]={k:money(total(v)) for k,v in sorted(cats.items())}
    unc=groups['category'].get('uncategorized',[]);out['uncategorized']={'count':len(unc),'total':money(total(unc)),'indexes':unc}
    dates=[day(r) for r in rows]; unique=sorted({d for d in dates if d});valid=[i for i,d in enumerate(dates) if d]
    out['date_range']={'start':unique[0].isoformat(),'end':unique[-1].isoformat()} if unique else None
    months=defaultdict(list);days=defaultdict(list)
    for i in valid:months[dates[i].isoformat()[:7]].append(i);days[dates[i].isoformat()].append(i)
    out['by_month']={k:money(total(v)) for k,v in sorted(months.items())};out['by_day']={k:money(total(v)) for k,v in sorted(days.items())};out['monthly_flow']={k:flow(v) for k,v in sorted(months.items())}
    out['activity']={'active_days':len(unique),'dated_rows':len(valid),'undated_rows':len(rows)-len(valid)}
    wk=[i for i in valid if dates[i].weekday()>=5];wf=flow(wk);out['weekend']={'count':len(wk),'spending':wf['spending'],'net':wf['net']}
    out['daily_average']=money(sum((amounts[i] for i in valid if amounts[i]>0),ZERO)/len(unique)) if unique else 0.0
    runs=[]
    for d in unique:
        if not runs or d!=runs[-1][-1]+timedelta(days=1):runs.append([d])
        else:runs[-1].append(d)
    best=min(runs,key=lambda x:(-len(x),x[0])) if runs else []
    out['longest_streak']={'days':len(best),'start':best[0].isoformat() if best else None,'end':best[-1].isoformat() if best else None}
    tax=[number(r.get('tax')) for r in rows];taxsum=sum(tax,ZERO);out['taxes']={'total':money(taxsum),'net_before_tax':money(sum(amounts,ZERO)-taxsum)}
    deductible=[i for i,r in enumerate(rows) if r.get('deductible') is True and amounts[i]>0];out['deductible']={'count':len(deductible),'spending':money(total(deductible)),'tax':money(sum((tax[i] for i in deductible),ZERO))}
    required=[i for i,a in enumerate(amounts) if a>=25];missing=[i for i in required if not label(rows[i],'receipt')];out['receipts']={'required':len(required),'missing':len(missing),'indexes':missing}
    ids=Counter(label(r,'id') for r in rows);out['duplicate_ids']={k:v for k,v in sorted(ids.items()) if k and v>1}
    invalid=[i for i,r in enumerate(rows) if label(r,'date') and dates[i] is None]
    out['data_quality']={'missing_amount':sum('amount' not in r or r['amount'] is None for r in rows),'invalid_dates':len(invalid),'missing_category':sum(not label(r,'category') for r in rows),'missing_currency':sum(not label(r,'currency') for r in rows)}
    originals={label(r,'id') for i,r in enumerate(rows) if amounts[i]>0 and label(r,'id')};refunds=[i for i,a in enumerate(amounts) if a<0];matched=[i for i in refunds if label(rows[i],'original_id') in originals];out['refund_links']={'matched':len(matched),'unmatched':len(refunds)-len(matched),'total_matched':money(-total(matched))}
    flags=[]
    for i,a in enumerate(amounts):
        reasons=[]
        if i in missing:reasons.append('missing_receipt')
        if a>=1000:reasons.append('large_expense')
        if i in invalid:reasons.append('invalid_date')
        if reasons:flags.append({'index':i,'reasons':reasons})
    out['review_flags']=flags
    allocations=defaultdict(lambda:ZERO);count=0;bad=[]
    for i,r in enumerate(rows):
        splits=r.get('allocations')
        if not isinstance(splits,dict) or not splits:continue
        vals={k:number(v) for k,v in splits.items()}
        if sum(vals.values(),ZERO)!=amounts[i]:bad.append(i);continue
        count+=1
        for k,v in vals.items():allocations[k]+=v
    out['split_allocations']={'valid_rows':count,'invalid_indexes':bad,'by_category':{k:money(v) for k,v in sorted(allocations.items())}}
    return out

def cases():
    yield 'empty',[],None
    yield 'missing',[{}, {'amount':None,'date':None,'category':' ','currency':''},{'amount':'','date':' '},{'amount':0,'category':'uncategorized','currency':'USD'}],{'unused':0}
    yield 'ties',[{'amount':x,'category':'food','tax':'0.005','merchant':' A '} for x in ['0.005','0.005','-0.005','1.005','-1.005','2.675']],{'food':'1.005'}
    yield 'boundaries',[{'amount':a,'date':d,'receipt':receipt,'id':str(i%3),'category':['a','b'][i%2]} for i,(a,d,receipt) in enumerate(zip(['-10','0','9.999','10','24.999','25','99.999','100','999.999','1000'],['2024-02-28','2024-02-29','2024-03-01','2025-12-31','2026-01-01','2026-01-02','2026-01-04','2026-01-05','2024-02-30','20240101'],[None,'r','',' ','r',None,'r','','','']))],{'a':0,'b':'99.995'}
    yield 'links-splits',[{'amount':'-3.005','original_id':' forward ','allocations':{'food':'-1.005','travel':'-2'}},{'amount':'25','id':'forward','deductible':True,'tax':'2.005','reimbursable':True,'reimbursed':True,'recurring':True,'allocations':{'food':10,'travel':15}},{'amount':10,'id':' forward ','reimbursable':1,'deductible':1,'recurring':1,'allocations':{'food':9}},{'amount':-2,'original_id':'absent'},{'amount':0,'allocations':{'zero':0}}],{'food':'8.5'}
    rng=random.Random(884332)
    for n in range(80):
        rows=[]
        for i in range(rng.randrange(1,45)):
            r={'amount':rng.choice(['-100.005','-3.5','-0.005','0','0.005','9.995','10','25','100','1000.005',None]),'category':rng.choice(['food','travel','a','uncategorized',None,' ',' food ']),'currency':rng.choice(['USD','SEK','eur',None,' ']),'merchant':rng.choice(['shop','cafe',' A ',None]),'payment_method':rng.choice(['card','cash',None]),'date':rng.choice(['2024-02-28','2024-02-29','2024-03-01','2025-12-31','2026-01-01','2026-01-04','2026-01-05','2026-01-06','2024-02-30','20240101',' ',None]),'tax':rng.choice(['0.005','0','-0.005','3.5',None]),'receipt':rng.choice(['r','',None]),'id':rng.choice(['one','two',' three ','',None]),'original_id':rng.choice(['one','two','missing','',None])}
            for flag in ['reimbursable','reimbursed','recurring','deductible']:r[flag]=rng.choice([True,False,1,'true',None])
            if rng.randrange(3)==0:
                amount=number(r['amount']);r['allocations']={'food':str(amount/2),'travel':str(amount/2+(Decimal('0.01') if rng.randrange(3)==0 else ZERO))}
            rows.append(r)
        yield f'seeded-{n}',rows,{'food':'25.005','travel':'100','absent':0}

def selfcheck():
    e=expected([],None);assert len(e)==34 and e['amount_stats']['median']==0 and e['longest_streak']['days']==0
    e=expected([{'amount':'0.005'},{'amount':'0.005'}]);assert e['total']==0.01 and e['amount_stats']['mean']==0.01
    e=expected([{'amount':-3,'original_id':'x'},{'amount':5,'id':'x'}]);assert e['refund_links']=={'matched':1,'unmatched':0,'total_matched':3.0}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('project');ap.add_argument('--features',default=','.join(FEATURES));ap.add_argument('--output');args=ap.parse_args();selfcheck()
    chosen=args.features.split(',') if args.features else [];keys=['count','total']+[FEATURES[f] for f in chosen]
    path=pathlib.Path(args.project)/'report.py';spec=importlib.util.spec_from_file_location('candidate_report',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    failures=[];runs=0
    for name,rows,budgets in cases():
        want=expected(rows,budgets)
        for generator in [False,True]:
            runs+=1
            try:
                inputs=json.loads(json.dumps(rows));actual=m.summarize((r for r in inputs) if generator else inputs,budgets=json.loads(json.dumps(budgets)))
                for key in keys:
                    if key not in actual or actual[key]!=want[key]:failures.append({'case':name,'generator':generator,'key':key,'expected':want[key],'actual':actual.get(key)})
            except Exception as exc:failures.append({'case':name,'generator':generator,'error':type(exc).__name__+': '+str(exc)})
    result={'spec_sha256':SPEC_SHA,'oracle_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'candidate_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'cases':runs,'features':chosen,'checks':runs*len(keys),'failures':failures,'pass':not failures}
    encoded=json.dumps(result,indent=2)
    if args.output:pathlib.Path(args.output).write_text(encoded)
    print(encoded);raise SystemExit(bool(failures))
if __name__=='__main__':main()
