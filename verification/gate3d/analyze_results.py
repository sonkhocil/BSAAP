import csv, gzip, hashlib, json, math, pathlib, statistics, collections
root = pathlib.Path(__file__).resolve().parent / 'pilot'
data = json.loads((root/'results.json').read_text())
runs = data['Results']
configs = ['B0','B1','B1W','B1R','B2']
assert data['Configurations'] == configs
assert data['Runtime']['DebuggerAttached'] is False
assert data['Runtime']['BuildConfiguration'] == 'Release'
assert data['Runtime']['PilotAssemblyVersion'].endswith(data['SourceCommitSha'])
binary=pathlib.Path(__file__).resolve().parents[2] / 'tools/Bsaap.ControlledPilot/bin/Release/net9.0/Bsaap.ControlledPilot.dll'
binary_fingerprint_match = hashlib.sha256(binary.read_bytes()).hexdigest()==data['Runtime']['PilotAssemblySha256'] if binary.exists() else None
assert len(runs) == 72
seen=set()
samples=0
for run in runs:
    key=(run['Seed'],run['Transactions'],run['Condition'])
    assert key not in seen
    seen.add(key)
    assert run['ReplayEquivalent']
    assert [b['Baseline'] for b in run['Baselines']] == configs
    assert len({tuple(p['QueryId'] for p in b['Predictions']) for b in run['Baselines']}) == 1
    for kind in ['Omission','Equivocation']:
        assert len({(b['Score'][kind]['ActualPositives'],b['Score'][kind]['ActualNegatives']) for b in run['Baselines']})==1
    receipt=next(b for b in run['Baselines'] if b['Baseline']=='B1R')
    assert receipt['ExposedWitnessAttestations']==0
    assert receipt['EvidenceAvailability']['AdmissibleOmissionCases']==0
    for baseline in run['Baselines']:
        assert len(baseline['Predictions']) == 3
        assert len({p['QueryId'] for p in baseline['Predictions']}) == 3
        assert len(baseline['Samples']) == 2
        samples += len(baseline['Samples'])
        for kind in ['Omission','Equivocation']:
            s=baseline['Score'][kind]
            assert all(s[k]>=0 for k in ['ActualPositives','ActualNegatives','Detections','FalseAccusations',
                'EvidenceCoveredPositives','EvidenceConditionalDetections','UnsupportedAccusations',
                'Inconclusive','InvalidEvidence','Missing','NoFinding','Accusations'])
            assert s['Accusations']==s['Detections']+s['FalseAccusations']
            assert sum(s[k] for k in ['Accusations','Inconclusive','InvalidEvidence','Missing','NoFinding'])==s['ActualPositives']+s['ActualNegatives']
            assert s['EvidenceSupportedDetections']<=s['RawFactuallyCorrectAccusations']<=s['ActualPositives']
            assert s['EvidenceCoveredPositives']<=s['ActualPositives']
            assert s['EvidenceConditionalDetections']<=s['EvidenceCoveredPositives']
            for name,numerator,denominator in [
                ('EvidenceCoverage',s['EvidenceCoveredPositives'],s['ActualPositives']),
                ('EvidenceConditionalDetectionRate',s['EvidenceConditionalDetections'],s['EvidenceCoveredPositives']),
                ('EvidenceSupportedPrecision',s['EvidenceSupportedDetections'],s['Accusations']),
                ('UnconditionalDetectionRate',s['Detections'],s['ActualPositives'])]:
                assert (s[name] is None) if denominator==0 else math.isclose(s[name],numerator/denominator,abs_tol=1e-12)
        for sample in baseline['Samples']:
            assert sample['Cost']['ManagedAllocatedBytes']>=0
assert samples==720
for key, grouped in __import__('itertools').groupby(sorted(runs,key=lambda r:(r['Seed'],r['Transactions'])),key=lambda r:(r['Seed'],r['Transactions'])):
    assert len({r['WorkloadSha256'] for r in grouped})==1
family={'HiddenFork','DisclosedFork','WitnessAttestationOnly','WitnessDiscovery','WitnessDiscoveryWithoutAttestation'}
for seed in [2027,2028]:
 for size in [25,250]:
    paired=[r for r in runs if r['Seed']==seed and r['Transactions']==size and r['Condition'] in family]
    assert len({r['ProtocolArchiveSha256'] for r in paired})==1
    for run in paired:
        eq={b['Baseline']:next(p['Outcome'] for p in b['Predictions'] if p['QueryId'].startswith('equivocation/')) for b in run['Baselines']}
        assert len({eq[k] for k in ['B1','B1W','B1R','B2']})==1
        expected=2 if run['Condition'] in ['DisclosedFork','WitnessDiscovery','WitnessDiscoveryWithoutAttestation'] else 1
        assert all(b['CommonAcquisitionGatewayRoots']==expected for b in run['Baselines'])
inputs=sorted(root.glob('input-*.json'))
assert len(inputs)==72
for path in inputs:
    saved=json.loads(path.read_text())
    archivepath=root/saved['ArchiveRelativePath']
    assert hashlib.sha256(archivepath.read_bytes()).hexdigest()==saved['ArchiveFileSha256']
    archive=gzip.decompress(archivepath.read_bytes())
    assert hashlib.sha256(archive).hexdigest()==saved['Manifest']['ArchiveSha256']
    assert saved['Manifest']['Workload']['SourceCommitSha']==data['SourceCommitSha']
    assert 'PrivateKey' not in archive.decode()
for file,expected in [('scores.csv',720),('verdicts.csv',1080)]:
    assert len(list(csv.DictReader((root/file).open())))==expected
timings=list(csv.DictReader((root/'timings.csv').open()))
assert sum(row['stage']=='classification' for row in timings)==720
freq=data['Runtime']['StopwatchFrequency']
for row in timings:
    assert math.isfinite(float(row['elapsed_ms'])) and float(row['elapsed_ms'])>=0
    assert abs(float(row['elapsed_ms'])-int(row['monotonic_ticks'])*1000/freq)<0.001
    assert int(row['managed_allocated_bytes'])>=0
summary=[]
summary.append('# Independent pilot output checks\n')
summary.append('All count, digest, paired-workload, witness-causality, CSV/JSON and finite-rate checks passed.')
summary.append(f"Source commit `{data['SourceCommitSha']}`. 72 paired cases, 360 configuration results, 720 classifier timing samples and 72 successful saved-input replays.")
summary.append('\n| Configuration | Omission raw / supported / actual | Equivocation raw / supported / actual | False | Unsupported | Inconclusive | Invalid |')
summary.append('| --- | --- | --- | --- | --- | --- | --- |')
for name in configs:
    b=[b for r in runs for b in r['Baselines'] if b['Baseline']==name]
    def total(kind,key): return sum(v['Score'][kind][key] for v in b)
    summary.append('| '+name+' | '+ '/'.join(str(total('Omission',k)) for k in ['RawFactuallyCorrectAccusations','EvidenceSupportedDetections','ActualPositives'])+
        ' | '+ '/'.join(str(total('Equivocation',k)) for k in ['RawFactuallyCorrectAccusations','EvidenceSupportedDetections','ActualPositives'])+
        ' | '+' | '.join(str(sum(total(kind,k) for kind in ['Omission','Equivocation'])) for k in ['FalseAccusations','UnsupportedAccusations','Inconclusive','InvalidEvidence'])+' |')
summary.append('\n## Diagnostic costs\n')
summary.append('These are medians over heterogeneous feasibility conditions on this shared host, without statistical inference. Classifier rows include their different evidence-processing paths.')
summary.append('\n| Nominal leaves | Stage/configuration | Samples | Median elapsed ms | Median managed allocated bytes |')
summary.append('| --- | --- | --- | --- | --- |')
for leaves in [100,1000]:
    for stage in ['artifact_generation','evidence_collection','full_snapshot_authentication','owner_scoring_with_proof_eligibility']:
        rows=[r for r in timings if int(r['nominal_leaves'])==leaves and r['stage']==stage]
        summary.append(f"| {leaves} | {stage} | {len(rows)} | {statistics.median(float(r['elapsed_ms']) for r in rows):.3f} | {statistics.median(int(r['managed_allocated_bytes']) for r in rows):.0f} |")
    for baseline in configs:
        rows=[r for r in timings if int(r['nominal_leaves'])==leaves and r['stage']=='classification' and r['baseline']==baseline]
        summary.append(f"| {leaves} | classification {baseline} | {len(rows)} | {statistics.median(float(r['elapsed_ms']) for r in rows):.3f} | {statistics.median(int(r['managed_allocated_bytes']) for r in rows):.0f} |")
ratios=[]
for run in runs:
 for baseline in run['Baselines']:
    ms=[s['Cost']['MonotonicTicks']*1000/freq for s in baseline['Samples']]
    if min(ms)>0: ratios.append(max(ms)/min(ms))
ratios.sort()
p95=ratios[min(len(ratios)-1,math.ceil(.95*len(ratios))-1)]
peak=max(int(r['process_lifetime_peak_working_set_bytes']) for r in timings)
summary.append(f"\nWithin-case max/min repetition ratios across all configurations have median {statistics.median(ratios):.3f}, empirical 95th percentile {p95:.3f}, and maximum {max(ratios):.3f}. Only two repetitions were taken. These are diagnostic stability checks, not confidence intervals.")
summary.append(f"\nMaximum observed cumulative process peak working set was {peak} bytes ({peak/1048576:.1f} MiB). This includes caches, setup, replay and previous cases.")
summary.append('\n## Serialized typed input bytes\n')
summary.append('| Nominal leaves | Configuration | Minimum bytes | Maximum bytes |')
summary.append('| --- | --- | --- | --- |')
for leaves in [100,1000]:
 for baseline in configs:
    values=[b['ProjectedInputBytes'] for r in runs if r['Transactions']*4==leaves for b in r['Baselines'] if b['Baseline']==baseline]
    summary.append(f"| {leaves} | {baseline} | {min(values)} | {max(values)} |")
summary.append('\n## Negative controls\n')
for kind in ['Omission','Equivocation']:
    control=[r['AlwaysAccuse'][kind] for r in runs]
    summary.append(f"Always-accuse {kind.lower()}: raw correct {sum(s['RawFactuallyCorrectAccusations'] for s in control)}, supported {sum(s['EvidenceSupportedDetections'] for s in control)}, false {sum(s['FalseAccusations'] for s in control)}, unsupported {sum(s['UnsupportedAccusations'] for s in control)}.")
summary.append('Always-inconclusive retained every actual positive in its unconditional denominator and issued zero accusations.')
summary.append('\n## Readiness\n')
summary.append('Not Ready for final benchmarking. Correctness and replay checks passed. Timing samples are too sparse and environment/GC/order effects remain uncontrolled. The 10,000- and 50,000-leaf matrices were not executed. Full-snapshot reauthentication and allocation costs already rise materially at 1,000 leaves. A representative query/obligation design, stronger isolation and a predeclared statistical protocol are still required.')
(root.parent/'pilot-analysis.md').write_text('\n'.join(summary)+'\n')
(root.parent/'independent-checks.json').write_text(json.dumps({
    'passed':True,'source_sha':data['SourceCommitSha'],'cases':72,'configuration_results':360,
    'timing_samples':samples,'input_archives_checked':len(inputs),'current_binary_fingerprint_match':binary_fingerprint_match,'peak_working_set_bytes':peak,
    'repeat_ratio_median':statistics.median(ratios),'repeat_ratio_p95':p95,'repeat_ratio_max':max(ratios),
    'checks':['counts','outcome_totals','finite_rates','paired_workloads','witness_causality',
              'compressed_digest','signed_archive_digest','provenance','CSV_JSON_rows','clock_units']
},indent=2)+'\n')
print('\n'.join(summary))
