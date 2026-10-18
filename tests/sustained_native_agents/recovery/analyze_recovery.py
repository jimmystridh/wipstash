#!/usr/bin/env python3
"""Separate recovery verification; never rewrites blind-phase analysis."""
import hashlib,importlib.util,json,pathlib,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parent
ORIGINAL=ROOT.parent

def readlines(path):
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []

def main():
    commands=readlines(ROOT/'actor-c-commands.jsonl');calls=[c for c in commands if c.get('kind')=='rpc'];ints=readlines(ROOT/'integrations.jsonl')
    accepted=[c for c in calls if c['request']['op'] in ('publish','resolution_submit') and c['response'].get('ok')]
    outcomes=[{'integration_started_epoch':i['started_epoch'],'integration_finished_epoch':i['finished_epoch'],**o} for i in ints for o in i['response'].get('outcomes',[])]
    opens=[c for c in calls if c['request']['op']=='open' and c['response'].get('ok')]
    tests=[c for c in commands if c.get('kind')=='tests']
    finished=json.loads((ROOT/'coordinator-summary.json').read_text())
    blind_manifest=json.loads((ORIGINAL/'blind-phase/MANIFEST.json').read_text())
    blind_hashes={name:hashlib.sha256((ORIGINAL/'blind-phase'/name).read_bytes()).hexdigest()==expected for name,expected in blind_manifest['sha256'].items()}
    # Invoke only the read-only privacy function, never analyze() or its CLI.
    spec=importlib.util.spec_from_file_location('blind_readonly_privacy',ORIGINAL/'harness/analyze.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    private=module.privacy_audit()
    new_manifests=[]
    for path in ROOT.glob('actor-c-recovery-*-private.json'):
        m=json.loads(path.read_text());ws=ROOT/m['workspace']
        unchanged={rel:hashlib.sha256((ws/rel).read_bytes()).hexdigest()==expected for rel,expected in m['files'].items()}
        p=subprocess.run(['git','--git-dir',str(ORIGINAL/'state/coordinator.git'),'cat-file','-e',m['private_checkpoint']['commit']],capture_output=True)
        new_manifests.append({'workspace':m['workspace'],'private_files_unchanged':unchanged,'private_checkpoint_absent_publicly':p.returncode!=0})
    winner=next((o for o in outcomes if o['state'] in ('integrated','already_included')),None)
    result={'kind':'separately_measured_oracle_guided_recovery','external_oracle_feedback_interventions':1,'blind_result_unchanged':'FAIL: 8 of 5,780 semantic assertions','core_policy_checks_configured':False,'source_projection_observed_in_recovery':False,'coordinator_elapsed_seconds':finished['seconds'],'automatic_integration_calls':len(ints),'integration_errors':sum(not i['response'].get('ok') for i in ints),'accepted_publications':len(accepted),'outcomes':outcomes,'tests':tests,'task_seconds':winner['integration_finished_epoch']-opens[0]['started_epoch'] if winner and opens else None,'publish_to_integrated_seconds':winner['integration_finished_epoch']-accepted[0]['finished_epoch'] if winner and accepted else None,'all_frozen_blind_evidence_hashes_unchanged':all(blind_hashes.values()),'frozen_evidence_files_verified':len(blind_hashes),'original_private_workspaces_still_intact':private['all_original_wip_hashes_unchanged'] and private['checkpoint_tracked_files_unchanged_except_designated_unsaved_marker'],'original_private_checkpoint_oids_still_absent_publicly':private['private_checkpoint_oids_absent_from_public_store'],'public_blobs_scanned_after_recovery':private['public_blobs_scanned'],'all_public_blobs_still_marker_free':private['all_public_blobs_marker_free'],'public_ref_private_paths':private['public_ref_tree_private_paths'],'new_private_manifests':new_manifests,'oracle_verification':'Independently run by parent; see recovery-oracle-result.json, not author tests.'}
    (ROOT/'recovery-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='tests'},indent=2))
if __name__=='__main__': main()
