import unittest
from src.models.reporting import historical_comparison, multiclass_tasks
from src.streaming.live_feature_extractor import LiveAfterImageExtractor


class TestAuditedPresentation(unittest.TestCase):
    def test_adaptive_row_does_not_borrow_base_metrics(self):
        rows=historical_comparison({'random_forest':{'f1_score':1.,'fpr':0.},
                                    'lodo_9_devices':{'rf_adaptive_f1_mean':.8,'rf_adaptive_fpr_mean':.1}})
        self.assertEqual(rows[-1]['LODO F1'],.8)
        for key in ['Test F1','FPR test','Train F1','Val F1','Latencia modelo (ms)']:
            self.assertIsNone(rows[-1][key])

    def test_original_and_canonical_tasks_are_distinct(self):
        rows=multiclass_tasks({'accuracy':.91,'f1_macro':.90,
                              'raw_10_classes_accuracy':.79,'raw_10_classes_f1_macro':.78})
        self.assertEqual(rows[0]['Accuracy'],.79)
        self.assertEqual(rows[1]['Accuracy'],.91)

    def test_jitter_count_preserved_and_unknown_schema_rejected(self):
        args=dict(src_mac='a',src_ip='1',dst_ip='2',src_port=1,dst_port=2,pkt_size=60.,timestamp=1.)
        e=LiveAfterImageExtractor(['HH_jit_L5_weight','HH_jit_L5_mean'])
        a=e.process_raw_packet(**args)
        self.assertEqual(a.iloc[0,0],1.)
        self.assertEqual(a.iloc[0,1],0.)
        self.assertFalse(e.production_ready)
        with self.assertRaises(ValueError):
            LiveAfterImageExtractor(['unknown_feature']).process_raw_packet(**args)


if __name__=='__main__':
    unittest.main()
