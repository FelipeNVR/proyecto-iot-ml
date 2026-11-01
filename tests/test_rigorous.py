"""Protocol invariants; no expected high score assertions."""
import unittest
import numpy as np
import pandas as pd
from src.models.rigorous import block_ranges, split_devices, threshold_from_calibration, metrics, feature_set, overlap_masks


class TestRigorousProtocol(unittest.TestCase):
    def test_blocks_disjoint_and_ordered(self):
        blocks=block_ranges(13113,True)
        self.assertEqual([b[0] for b in blocks],['train']*2+['calibration']*2+['test']*2)
        for a,b in zip(blocks,blocks[1:]):
            self.assertLess(a[2],b[1])
        with self.assertRaises(ValueError):
            block_ranges(100,True)

    def test_device_roles_never_overlap_all_folds(self):
        df=pd.DataFrame([{'device':i,'partition':p} for i in range(1,10)
                         for p in ['train','calibration','test']])
        for held in range(1,10):
            tr,va,te=split_devices(df,held)
            self.assertEqual(len(tr),6); self.assertEqual(len(va),2)
            self.assertEqual(te.device.tolist(),[held])
            self.assertFalse(set(tr.device)&set(va.device))

    def test_threshold_handles_ties_and_no_possible_alarm(self):
        y=np.array([0,0,0,1]); p=np.array([.9,.9,1.,.8])
        t=threshold_from_calibration(y,p,0)
        self.assertGreater(t,1.)
        m=metrics(y,p,t)
        self.assertEqual(m['fp'],0); self.assertEqual(m['fn'],1)
        self.assertIsNone(m['precision'])
        with self.assertRaises(ValueError):
            threshold_from_calibration([1],[.8])

    def test_threshold_empirical_fpr_budget(self):
        p=np.linspace(0,1,1001); y=np.zeros(len(p))
        t=threshold_from_calibration(y,p,.01)
        self.assertLessEqual(np.mean(p>=t),.01)

    def test_undefined_metrics_stay_missing(self):
        m=metrics([0,0],[.1,.8],.5)
        self.assertIsNone(m['recall']); self.assertIsNone(m['roc_auc'])
        self.assertIsNone(m['f1']); self.assertEqual(m['fpr'],.5)
        self.assertEqual(metrics([],[],.5)['n'],0)

    def test_overlap_ignores_label_and_metadata(self):
        tr=pd.DataFrame({'x':[1.,2.],'target':[0,0]})
        va=pd.DataFrame({'x':[2.,3.],'target':[1,1]})
        te=pd.DataFrame({'x':[3.,4.],'target':[0,1]})
        a,b=overlap_masks(tr,va,te,['x'])
        self.assertEqual(a.tolist(),[True,False]); self.assertEqual(b.tolist(),[True,False])

    def test_feature_policy_preserves_weight_excludes_epoch(self):
        cols=['HH_jit_L5_weight','HH_jit_L5_mean','HH_jit_L5_variance','H_L5_mean']
        self.assertEqual(feature_set(cols),['HH_jit_L5_weight','H_L5_mean'])
        self.assertEqual(feature_set(cols,'no_weights'),['H_L5_mean'])


if __name__=='__main__':
    unittest.main()
