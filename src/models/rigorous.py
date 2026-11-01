"""Benchmark de desarrollo por bloques y dispositivos. Nunca promueve modelos a producción.

Ejecutar: python -m src.models.rigorous --output experiments/rigorous_v1
No sintetiza tráfico ni altera etiquetas. Los porcentajes son posiciones, no tiempos.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (confusion_matrix, f1_score, accuracy_score,
                             average_precision_score, roc_auc_score, brier_score_loss)

ROOT = Path(__file__).resolve().parents[2]
META = ['device', 'source', 'row', 'partition', 'family', 'attack', 'target']
PLAN = {
    'version': 1, 'seed': 42,
    'blocks': {'train': [.10, .30], 'calibration': [.50, .65], 'test': [.80, .95]},
    'rows_per_attack_block': 200, 'rows_per_benign_block': 1000,
    'calibration_empirical_fpr_budget': .001,
    'models': ['lr', 'rf', 'gb'],
    'outer_devices': list(range(1, 10)),
    'inner_calibration': 'next two device IDs cyclically; other six fit the model',
    'unknown_family': ['gafgyt', 'mirai'],
    'notes': ['development benchmark, not an untouched production acceptance set',
              'no timestamps: positional gaps are not verified temporal embargoes',
              'fixed samples per file do not represent deployment prevalence',
              'all model and threshold choices frozen before evaluating test'],
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def save_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False,
                                    allow_nan=False), encoding='utf-8')


def block_ranges(n, benign, plan=PLAN):
    width = plan['rows_per_benign_block' if benign else 'rows_per_attack_block']
    ranges = [(partition, int(n*f), min(n, int(n*f)+width))
              for partition, fractions in plan['blocks'].items() for f in fractions]
    for a, b in zip(ranges, ranges[1:]):
        if a[2] >= b[1]:
            raise ValueError(f'Insufficient capture length for disjoint blocks: {n}')
    return ranges


def collect(data_dir, output):
    """Read every row once for quality; retain only prespecified contiguous blocks."""
    summary = pd.read_csv(data_dir/'data_summary.csv')
    summary.columns = summary.columns.str.strip()
    pieces, manifest = [], []
    feature_cols = None
    for record in summary.to_dict('records'):
        name, expected = record['File Name'].strip(), int(record['Data Count'])
        path = data_dir/name
        before = (path.stat().st_size, path.stat().st_mtime_ns)
        digest = sha256(path)
        device = int(name.split('.')[0]); benign = '.benign.' in name
        family = 'benign' if benign else name.split('.')[1]
        ranges = block_ranges(expected, benign)
        offset, bad_count, selected_bad = 0, 0, 0
        for chunk in pd.read_csv(path, chunksize=20000, dtype='float64'):
            if feature_cols is None:
                feature_cols = list(chunk.columns)
                if len(feature_cols) != 115:
                    raise ValueError('Expected 115 features')
            if list(chunk.columns) != feature_cols:
                raise ValueError(f'Feature schema/order mismatch: {name}')
            finite = np.isfinite(chunk.to_numpy()).all(axis=1)
            bad_count += int((~finite).sum())
            for partition, start, stop in ranges:
                lo, hi = max(start-offset, 0), min(stop-offset, len(chunk))
                if lo >= hi:
                    continue
                x = chunk.iloc[lo:hi].copy()
                valid = finite[lo:hi]
                selected_bad += int((~valid).sum())
                x = x.assign(device=device, source=name,
                             row=np.arange(offset+lo, offset+hi), partition=partition,
                             family=family, attack='benign' if benign else '.'.join(name.split('.')[1:3]),
                             target=int(not benign))
                pieces.append(x.loc[valid])
            offset += len(chunk)
        if offset != expected or before != (path.stat().st_size, path.stat().st_mtime_ns):
            raise ValueError(f'File changed or count mismatch: {name}: {offset} != {expected}')
        manifest.append({'file': name, 'sha256': digest, 'size_bytes':before[0],
                         'rows': offset, 'nonfinite_rows_full_file':bad_count,
                         'nonfinite_selected_rows_excluded':selected_bad, 'ranges':ranges})
        print(f'[data] {name}: {offset} rows inspected', flush=True)
    frame = pd.concat(pieces, ignore_index=True)
    if frame.duplicated(['source','row']).any():
        raise ValueError('A source row appears in multiple partitions')
    save_json(output/'data_manifest.json', manifest)
    save_json(output/'features_raw.json', feature_cols)
    # Audit cache; not a deployment input. Preserve original feature values for ablations.
    frame.to_pickle(output/'selected_rows.pkl')
    return frame, feature_cols


def feature_set(columns, variant='sanitized'):
    if variant == 'raw_jitter':
        return list(columns)
    keep = [c for c in columns if not (c.startswith('HH_jit_') and c.endswith(('_mean','_variance')))]
    if variant == 'no_weights':
        keep = [c for c in keep if not c.endswith('_weight')]
    elif variant == 'no_slow_windows':
        keep = [c for c in keep if '_L0.01_' not in c and '_L0.1_' not in c]
    return keep


def model_factory(name):
    if name == 'lr':
        return make_pipeline(StandardScaler(), LogisticRegression(C=.1, max_iter=2000,
                                                                  class_weight='balanced', random_state=42))
    if name == 'rf':
        return RandomForestClassifier(n_estimators=100, max_depth=8, min_samples_leaf=10,
                                      max_features='sqrt', class_weight='balanced',
                                      random_state=42, n_jobs=2)
    if name == 'gb':
        return HistGradientBoostingClassifier(max_iter=100, max_depth=6,
                                              min_samples_leaf=20, class_weight='balanced', random_state=42)
    raise ValueError(name)


def threshold_from_calibration(y, probs, budget=.001):
    """Smallest threshold with empirical benign FPR <= budget. No test or train labels."""
    y, probs = np.asarray(y), np.asarray(probs)
    if len(y) == 0 or not np.any(y == 0):
        raise ValueError('Independent benign calibration rows required')
    if not np.isfinite(probs).all() or ((probs<0)|(probs>1)).any():
        raise ValueError('Invalid probability')
    b = np.sort(probs[y == 0])[::-1]
    allowed = int(np.floor(budget*len(b)))
    if not 0 <= budget < 1:
        raise ValueError('FPR budget must be in [0,1)')
    return float(np.nextafter(b[allowed], np.inf))


def metrics(y, probs, threshold):
    y, probs = np.asarray(y), np.asarray(probs)
    if not len(y):
        return {'n':0, 'status':'no rows; not evaluated'}
    pred = probs >= threshold
    tn,fp,fn,tp = map(int, confusion_matrix(y, pred, labels=[0,1]).ravel())
    both = len(np.unique(y)) == 2
    return {'n':len(y), 'tn':tn,'fp':fp,'fn':fn,'tp':tp,
            'f1':float(f1_score(y,pred,zero_division=0)) if np.any(y==1) else None,
            'accuracy':float(accuracy_score(y,pred)),
            'precision':float(tp/(tp+fp)) if tp+fp else None,
            'recall':float(tp/(tp+fn)) if tp+fn else None,
            'fpr':float(fp/(fp+tn)) if fp+tn else None,
            'roc_auc':float(roc_auc_score(y,probs)) if both else None,
            'average_precision':float(average_precision_score(y,probs)) if both else None,
            'brier':float(brier_score_loss(y,probs)),
            'threshold':threshold}


def split_devices(frame, held):
    cal = [held % 9 + 1, (held+1) % 9 + 1]
    train = [i for i in range(1,10) if i not in [held]+cal]
    tr=frame[(frame.device.isin(train)) & (frame.partition=='train')]
    va=frame[(frame.device.isin(cal)) & (frame.partition=='calibration')]
    te=frame[(frame.device==held) & (frame.partition=='test')]
    assert set(tr.device).isdisjoint(va.device) and set(te.device).isdisjoint(set(tr.device)|set(va.device))
    return tr,va,te


def overlap_masks(tr, va, te, columns, rounded=False):
    """Feature-vector overlap, excluding labels. Rounded version is only a sensitivity proxy."""
    def h(df):
        x=df[columns]
        if rounded:
            # Six significant digits: a declared numerical proxy, not a physical distance.
            x=x.map(lambda v: float(f'{v:.6g}'))
        return pd.util.hash_pandas_object(x,index=False)
    a,b,c=h(tr),h(va),h(te)
    return b.isin(set(a)).to_numpy(), c.isin(set(a)|set(b)).to_numpy()


def experiment(frame, columns, output, name, tr, va, te, model_name='rf', variant='sanitized'):
    if min(len(tr),len(va),len(te)) == 0:
        raise ValueError(f'Empty split: {name}')
    cols = feature_set(columns,variant)
    model=model_factory(model_name)
    started=time.perf_counter(); model.fit(tr[cols],tr.target)
    fit_seconds=time.perf_counter()-started
    pv=model.predict_proba(va[cols])[:,1]
    threshold=threshold_from_calibration(va.target,pv,PLAN['calibration_empirical_fpr_budget'])
    # Freeze model and threshold before first test prediction.
    meta={'name':name,'model':model_name,'variant':variant,'features':cols,
          'threshold':threshold, 'seed':42,'fit_seconds':fit_seconds,
          'train_devices':sorted(map(int,tr.device.unique())),
          'calibration_devices':sorted(map(int,va.device.unique())),
          'test_devices':sorted(map(int,te.device.unique())),
          'train_families':sorted(tr.family.unique()),'test_families':sorted(te.family.unique()),
          'counts':{'train':len(tr),'calibration':len(va),'test':len(te)},
          'production_ready':False}
    exp_dir=output/name; exp_dir.mkdir()
    joblib.dump({'model':model,'features':cols,'threshold':threshold,'metadata':meta},exp_dir/'candidate.joblib')
    save_json(exp_dir/'configuration.json',meta)
    pt=model.predict_proba(te[cols])[:,1]
    cv_overlap, test_overlap=overlap_masks(tr,va,te,cols)
    result={**meta, 'calibration':metrics(va.target,pv,threshold),
            'test_fixed_0_5':metrics(te.target,pt,.5),
            'test_calibrated':metrics(te.target,pt,threshold),
            'test_without_exact_development_matches':metrics(te.target.to_numpy()[~test_overlap],pt[~test_overlap],threshold),
            'overlap':{'calibration_matches_train':int(cv_overlap.sum()),
                       'test_matches_train_or_calibration':int(test_overlap.sum())},
            'by_capture':{src:metrics(te.target.to_numpy()[te.source.to_numpy()==src],pt[te.source.to_numpy()==src],threshold)
                          for src in sorted(te.source.unique())}}
    predictions=te[META].copy()
    predictions['probability_attack']=pt
    predictions['prediction']=pt>=threshold
    predictions['matches_development_vector']=test_overlap
    predictions.to_csv(exp_dir/'predictions.csv.gz',index=False)
    save_json(exp_dir/'metrics.json',result)
    print(f'[eval] {name}: F1={result["test_calibrated"]["f1"]} FPR={result["test_calibrated"]["fpr"]}',flush=True)
    return result


def run(output):
    output.mkdir(parents=True,exist_ok=False)
    save_json(output/'protocol_before_test.json',PLAN)
    save_json(output/'environment.json',{'python':platform.python_version(),'sklearn':sklearn.__version__,
                                      'numpy':np.__version__,'pandas':pd.__version__,
                                      'code_sha256':sha256(Path(__file__))})
    frame,cols=collect(ROOT/'data',output)
    results=[]
    # Common chronological test: future blocks in the same captures; report as such.
    tr=frame[frame.partition=='train']; va=frame[frame.partition=='calibration']; te=frame[frame.partition=='test']
    for model in PLAN['models']:
        results.append(experiment(frame,cols,output,f'temporal_{model}',tr,va,te,model))
    # Stronger external device evaluation: 6 fit / 2 calibrate / 1 test, fixed rotation.
    for held in PLAN['outer_devices']:
        tr,va,te=split_devices(frame,held)
        for model in PLAN['models']:
            results.append(experiment(frame,cols,output,f'device_{held}_{model}',tr,va,te,model))
        # Exclude an entire botnet from fitting AND calibration, test it on an unseen device.
        for family in PLAN['unknown_family']:
            unknown_test=te[(te.family==family)|(te.target==0)]
            if not (unknown_test.target==1).any():
                continue
            results.append(experiment(frame,cols,output,f'unknown_{family}_device_{held}_rf',
                                      tr[tr.family!=family],va[va.family!=family],unknown_test,'rf'))
    # Prespecified exploratory ablations on every outer device. Do not select using these test results.
    for variant in ['raw_jitter','no_weights','no_slow_windows']:
        for held in PLAN['outer_devices']:
            tr,va,te=split_devices(frame,held)
            results.append(experiment(frame,cols,output,f'ablation_{variant}_device_{held}',tr,va,te,'rf',variant))
    rows=[]
    for r in results:
        for rule in ['test_fixed_0_5','test_calibrated','test_without_exact_development_matches']:
            rows.append({'experiment':r['name'],'rule':rule,**r[rule]})
    pd.DataFrame(rows).to_csv(output/'summary.csv',index=False)
    save_json(output/'results.json',results)
    save_json(output/'status.json',{'completed':True,'experiments':len(results),'production_ready':False,
        'missing_evidence':['independent local PCAP sessions','validated identical offline/online extractor',
                            'event labels and timing','operational false alarms/hour and detection delays']})


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    run(args.output.resolve())
