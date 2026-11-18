import json

import joblib
import numpy as np
import pandas as pd
import pytest

from ml.train import train
from ml.volume import intensity, fit_representation, VOLUME_FEATURES
from scripts.run_volume_experiment import jobs
from waf.features import FEATURES_BASE
from waf.scoring import Scorer


def test_volume_scaling_fits_only_training_and_loader_matches_batch(tmp_path):
    rng=np.random.default_rng(42);rows=[]
    for group in ['fit','cal']:
        for i in range(200):
            row={f:0 for f in FEATURES_BASE}
            row.update(req_10s=float(rng.uniform(1,10)),req_60s=float(rng.uniform(1,60)),
                       task_token_budget=float(rng.uniform(0,20000)),run_id=group,
                       label='benign',feature_version=3)
            rows.append(row)
    frame=pd.DataFrame(rows);csv=tmp_path/'data.csv';frame.to_csv(csv,index=False)
    split=tmp_path/'splits.json';split.write_text(json.dumps({'benign_fit':['fit'],
        'benign_calibration':['cal'],'test':['new-test']}))
    model=tmp_path/'model.joblib'
    manifest=train(csv,model,splits_path=split,feature_set='volume',calibration_percentile=5)
    expected=fit_representation(frame[frame.run_id=='fit'][VOLUME_FEATURES].to_numpy())
    assert manifest['volume_parameters']==expected
    scorer=Scorer(model); assert scorer.model.n_features_in_==1
    sample=rows[:10];assert np.array_equal(scorer.score_many(sample),[scorer.score(r) for r in sample])
    low={f:0 for f in FEATURES_BASE};assert scorer.score(low)==0 and not scorer.is_anomalous(0)
    high={**low,'req_10s':10000,'req_60s':10000}
    assert scorer.is_anomalous(scorer.score(high))
    artifact=joblib.load(model);artifact['volume_parameters']['scales'][0]=0
    joblib.dump(artifact,model)
    with pytest.raises(ValueError,match='volume manifest'):Scorer(model)


@pytest.mark.parametrize('x,scales',[(np.array([[-1,0,0]]),[1,1,1]),
    (np.zeros((1,2)),[1,1,1]),(np.zeros((1,3)),[1,np.nan,1])])
def test_volume_rejects_bad_representation(x,scales):
    with pytest.raises(ValueError):intensity(x,scales)


def test_predeclared_volume_groups_are_disjoint_and_complete():
    planned=jobs();assert len(planned)==21
    ids=[j['run_id'] for j in planned];assert len(set(ids))==21
    parts={part:{j['seed'] for j in planned if j['split']==part} for part in ['fit','calibration','test']}
    assert not parts['fit'] & parts['calibration'] and not parts['test'] & (parts['fit']|parts['calibration'])
    assert not set.union(*parts.values()) & {101,102,103,201,202,203,301,302,303,401,402,403,601,602,603}
