#!/usr/bin/env python3
"""Independent CLI consistency check: registry, defaults, dispatch, gates, config, evidence."""
import argparse, hashlib, json, pathlib, subprocess, tempfile
from validate import C
HERE=pathlib.Path(__file__).resolve().parent
DEFAULT={'CWE-116/replace-escaping','CWE-79/cmark-unsafe'}
GATED={'CWE-79/cmark-unsafe','CWE-79/inner-html','CWE-79/template-injection','CWE-942/cors-credentials','CWE-614/cookie-attrs','CWE-346/ws-origin','CWE-770/no-body-limit'}
STDLIB_GATED={'CWE-676/unsafe-call','CWE-248/panic-reachable','CWE-704/unsafe-cast'}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--analyzer',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);args=ap.parse_args()
    rows=[];caps=None;cases=[x for x in C if x['kind']=='dangerous_shape'];ids={x['rule'] for x in cases}
    with tempfile.TemporaryDirectory(prefix='moon-registry-audit-') as tmp:
        root=pathlib.Path(tmp);(root/'moon.mod').write_text('name = "audit/rules"\nversion = "0.0.1"\n');(root/'moon.pkg').write_text('import { "audit/rules/mocket_cmark_rabbita_crescent" }\n')
        for case in cases:
            rid=case['rule'];(root/'probe.mbt').write_text(case['source']+'\n')
            for mode in ['default','explicit','config_enable','config_disable','missing_gate','stdlib_gate','severity_info']:
                extras=[];enabled=rid in DEFAULT; expected_count=int(enabled);expected_status='evaluated' if enabled else 'disabled'
                (root/'moon.pkg').write_text('import { "audit/rules/mocket_cmark_rabbita_crescent" }\n')
                (root/'moon.mod').write_text('name = "audit/rules"\nversion = "0.0.1"\n')
                if mode in ['explicit','missing_gate','stdlib_gate','severity_info']:
                    extras=['--rule',rid];expected_count=1;expected_status='evaluated'
                if mode.startswith('config_'):
                    enabled=mode=='config_enable';expected_count=int(enabled);expected_status='evaluated' if enabled else 'disabled'
                    cfg=root/'config.json';cfg.write_text(json.dumps({'rules':{rid:{'enabled':enabled}}}));extras=['--config',str(cfg)]
                if mode=='missing_gate':
                    (root/'moon.pkg').write_text('')
                    if rid in GATED: expected_count=0;expected_status='gated_out'
                if mode=='stdlib_gate':
                    (root/'moon.mod').write_text('name = "moonbitlang/core"\nversion = "0.0.1"\n')
                    if rid in STDLIB_GATED:expected_count=0;expected_status='gated_out'
                if mode=='severity_info':
                    cfg=root/'config.json';cfg.write_text(json.dumps({'rules':{rid:{'enabled':True,'severity':'info'}}}));extras=['--config',str(cfg),'--severity','info'];expected_count=1;expected_status='evaluated'
                cmd=[str(args.analyzer.resolve()),str(root),'--format','json','--quiet']+extras
                run=subprocess.run(cmd,text=True,capture_output=True,timeout=30)
                report=json.loads(run.stdout);manifest=report['analysis_manifest'];current_caps=manifest['rule_capabilities'];current_ids={x['id'] for x in current_caps}
                if caps is None:caps=current_caps
                coverage=next(x['rules'] for x in manifest['files'] if x['path'].endswith('/probe.mbt'));entry=next(x for x in coverage if x['id']==rid)
                findings=[x for x in report['findings'] if x['rule_id']==rid]
                reasons=[]
                if len(findings)!=expected_count:reasons.append('finding_count')
                if entry['status']!=expected_status:reasons.append('coverage_status')
                if len(current_caps)!=14 or current_ids!=ids:reasons.append('registry_ids')
                if current_caps!=caps:reasons.append('registry_changes_with_selection')
                if {x['id'] for x in current_caps if x['default_enabled']}!=DEFAULT:reasons.append('registry_defaults')
                if any(x['evidence']!='syntax_hint' for x in current_caps):reasons.append('registry_evidence')
                if len(coverage)!=14 or {x['id'] for x in coverage}!=ids:reasons.append('coverage_ids')
                if any(x.get('evidence')!='syntax_hint' for x in findings):reasons.append('finding_evidence')
                if report['errors'] or run.returncode!=0:reasons.append('scan_failure')
                if mode=='severity_info' and any(x.get('severity')!='info' for x in findings):reasons.append('configured_severity_ignored')
                if mode=='explicit' and any(x['status']!='disabled' for x in coverage if x['id']!=rid):reasons.append('explicit_leaked_rules')
                rows.append(dict(rule=rid,mode=mode,findings=len(findings),expected_findings=expected_count,coverage_status=entry['status'],expected_coverage_status=expected_status,passed=not reasons,failures=reasons))
    record=dict(schema='moon-audit.registry-acceptance.v1',analyzer_sha256=hashlib.sha256(args.analyzer.read_bytes()).hexdigest(),purpose='Dispatch and policy consistency; not vulnerability detection accuracy.',capabilities=caps,cases=rows,passed=sum(x['passed'] for x in rows),total=len(rows))
    args.output.write_text(json.dumps(record,indent=2)+'\n');print(f"Registry acceptance: {record['passed']}/{record['total']}")
    for row in rows:
        if not row['passed']:print(row)
    return 0 if record['passed']==record['total'] else 1
if __name__=='__main__':raise SystemExit(main())
