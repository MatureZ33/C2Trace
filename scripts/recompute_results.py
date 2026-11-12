"""Recompute trial/case metrics and costs from the selected retained score files.

No API keys, model calls, live targets or third-party Python packages are needed.
This aggregates retained scoring decisions; it does not recreate host observations.
"""
import argparse
import collections
import csv
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('tp','fp','fn','precision','recall','f1')
COSTS = ('llm_calls','tool_calls','prompt_tokens','completion_tokens','total_tokens',
         'case_duration_ms','end_to_end_duration_ms','investigation_duration_ms',
         'response_duration_ms','verification_duration_ms')
TOKEN_COSTS = ('prompt_tokens','completion_tokens','total_tokens')

def read(p): return json.loads(p.read_text(encoding='utf-8-sig'))
def metrics(tp,fp,fn):
    precision=tp/(tp+fp) if tp+fp else None
    recall=tp/(tp+fn) if tp+fn else None
    f1=None if precision is None or recall is None else 2*precision*recall/(precision+recall) if precision+recall else 0.0
    return dict(zip(FIELDS,(tp,fp,fn,precision,recall,f1)))
def same(a,b):
    return a is None and b is None or isinstance(a,(int,float)) and isinstance(b,(int,float)) and math.isclose(a,b,rel_tol=1e-9,abs_tol=1e-9)
def score_metric(score,kind):
    prefix='trace' if kind=='trace' else 'response_action'
    result=metrics(*(score['counts'][prefix+'_'+k] for k in FIELDS[:3]))
    for k in FIELDS[3:]:
        assert same(result[k],score['metrics'][prefix+'_'+k]),(score['case_id'],prefix,k)
    return result
def pooled(rows,kind):
    return metrics(*(sum(r[kind][k] for r in rows) for k in FIELDS[:3]))

def run():
    reference=read(ROOT/'data/paper_reference_metrics.json')
    inventory=read(ROOT/'data/inventory.json')
    rows=[]
    for entry in inventory:
        path=ROOT/entry['path']
        if not (path/'score.json').exists():
            raise FileNotFoundError('Run python scripts/extract_artifacts.py first: '+entry['path'])
        score=read(path/'score.json')
        row=dict(entry)
        row['trace']=score_metric(score,'trace')
        if entry['experiment']=='llm_direct':
            action=read(path/'proposed_action_score.json')
            row['response']=metrics(*(action[k] for k in FIELDS[:3]))
            for k in FIELDS: assert same(row['response'][k],action[k])
            call=read(path/'llm_call.json')
            row['cost']={**call['usage'],'llm_calls':1,'tool_calls':0,'duration_ms':call['duration_ms']}
            row['poststate_passed']=None
            expected=reference['direct']['per_case'][entry['case_id']]
        else:
            row['response']=score_metric(score,'response')
            row['cost']=read(path/'operational_metrics.json')['metrics']
            if entry['experiment']=='ablation':
                outcome=read(path/'trial_result.json')
                assert outcome['infrastructure_valid'] is True,entry
                assert outcome['include_in_evaluation_denominator'] is True,entry
                assert outcome['run_id']==entry['run_id'],entry
                row['cleanup_completed']=outcome.get('cleanup_completed')
                if not entry['token_usage_available']:
                    # Keep original records unchanged. These zero fields reflect
                    # unavailable usage after transport failure, not measured zero.
                    row['raw_recorded_tokens']={k:row['cost'][k] for k in TOKEN_COSTS}
                    assert all(v==0 for v in row['raw_recorded_tokens'].values()),entry
                    row['cost']={**row['cost'],**dict.fromkeys(TOKEN_COSTS)}
            post=read(path/'post_response_validation.json')
            row['poststate_passed']=post.get('passed')
            if entry['experiment']=='effect': expected=reference['rq1']['per_case'][entry['case_id']]
            elif entry['experiment']=='ablation': expected=reference['ablation']['per_trial'][entry['run_id']]
            else: expected=None
        if expected:
            for kind in ['trace','response']:
                for k in FIELDS: assert same(row[kind][k],expected[kind][k]),(entry,kind,k)
            for k,v in expected.get('cost',{}).items():
                if k in row['cost']: assert same(row['cost'][k],v),(entry,k)
        row['trial_class']=score.get('trial_class')
        rows.append(row)
    populations=collections.Counter(r['experiment'] for r in rows)
    assert populations=={'effect':8,'baseline':48,'ablation':96,'llm_direct':8},populations
    ablation=[r for r in rows if r['experiment']=='ablation']
    assert collections.Counter(r['system'] for r in ablation)==dict.fromkeys(('FULL','A1','A2','A3'),24)
    assert len({(r['system'],r['case_id'],r['repeat']) for r in ablation})==96
    assert sum(not r['token_usage_available'] for r in ablation)==4
    groups=collections.defaultdict(list)
    for r in rows:groups[(r['experiment'],r['system'])].append(r)
    summaries={};case_rows=[]
    for (experiment,system),members in groups.items():
        cases=collections.defaultdict(list)
        for r in members: cases[r['case_id']].append(r)
        local=[]
        for cid,cr in cases.items():
            item={'experiment':experiment,'system':system,'case_id':cid,'n':len(cr),
                  'trace':pooled(cr,'trace'),'response':pooled(cr,'response')}
            item['cost']={k:{'n_defined':sum(r['cost'].get(k) is not None for r in cr),
              'sum':sum(r['cost'][k] for r in cr if r['cost'].get(k) is not None)} for k in COSTS}
            local.append(item);case_rows.append(item)
        summary={'n':len(members),'cases':len(cases),'trace':pooled(members,'trace'),'response':pooled(members,'response'),
          'poststate_passed':sum(r['poststate_passed'] is True for r in members),
          'poststate_defined':sum(r['poststate_passed'] is not None for r in members),
          'trial_classes':dict(collections.Counter(r['trial_class'] for r in members)),
          'macro':{},'cost':{}}
        for kind in ['trace','response']:
            summary['macro'][kind]={}
            for k in FIELDS[3:]:
                values=[r[kind][k] for r in local if r[kind][k] is not None]
                summary['macro'][kind][k]={'n_defined':len(values),'mean':sum(values)/len(values) if values else None}
        for k in COSTS:
            values=[r['cost'][k] for r in members if r['cost'].get(k) is not None]
            total=sum(values) if values else None
            mean_defined=sum(values)/len(values) if values else None
            summary['cost'][k]={'n_defined':len(values),'sum':total,'mean':mean_defined}
            if experiment=='ablation' and k in TOKEN_COSTS:
                summary['cost'][k].update(mean=total/len(members) if total is not None else None,
                    mean_recorded_per_trial=total/len(members) if total is not None else None,
                    mean_defined=mean_defined, n_usage_unavailable=len(members)-len(values))
        if experiment=='ablation':
            expected=reference['ablation']['variants'][system]
            for kind in ('trace','response'):
                for k in FIELDS: assert same(summary[kind][k],expected[kind][k]),(system,kind,k)
                assert same(summary['macro'][kind]['f1']['mean'],expected['macro'][kind]['f1'])
                assert summary['macro'][kind]['f1']['n_defined']==expected['macro'][kind]['n_defined']
            assert summary['poststate_passed']==expected['poststate_passed']
            assert summary['poststate_defined']==24
            for k,cost in expected['cost'].items():
                for field in ('sum','mean','n_defined'):
                    assert same(summary['cost'][k][field],cost[field]),(system,k,field)
            for item in local:
                case_expected=reference['ablation']['per_case'][item['case_id']][system]
                assert item['n']==3
                for kind in ('trace','response'):
                    for k in FIELDS: assert same(item[kind][k],case_expected[kind][k])
        summaries[experiment+'/'+system]=summary
    for system in ['c2trace','react']:
        got=summaries['baseline/'+system]
        for kind in ['trace','response']:
            expected=reference['baseline']['pooled_micro'][system][kind]
            for k in FIELDS: assert same(got[kind][k],expected[k]),(system,kind,k)
    return rows,case_rows,summaries

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'results/recomputed')
    args=parser.parse_args()
    rows,cases,summary=run();args.output.mkdir(parents=True,exist_ok=True)
    for name,obj in [('trials',rows),('per_case',cases),('summary',summary)]:
        (args.output/(name+'.json')).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    flat=[]
    for r in rows:
        item={k:r.get(k) for k in ['experiment','system','source_variant','source_campaign','case_id','trial_id','run_id','trial_class','poststate_passed','token_usage_available']}
        for kind in ['trace','response']:
            item.update({kind+'_'+k:v for k,v in r[kind].items()})
        item.update({k:r['cost'].get(k) for k in COSTS});flat.append(item)
    with (args.output/'per_trial_metrics.csv').open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(flat[0]));writer.writeheader();writer.writerows(flat)
    print(f'Validated {len(rows)} selected records; wrote metrics and costs to {args.output}')
    for key,v in summary.items():
        print(f'{key}: n={v["n"]}, Trace={v["trace"]}, Response={v["response"]}')

if __name__=='__main__':main()
