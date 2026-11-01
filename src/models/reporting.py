"""Presentation of historical results without inventing measurements."""
def historical_comparison(metrics):
    lodo=metrics.get('lodo_9_devices',{})
    rows=[]
    for label,key,fold in [
        ('Dummy','dummy_majority',None),('Regresión logística','baseline_logistic_regression','lr'),
        ('SVM calibrado','svm_calibrated','svm'),('Árbol','decision_tree','dt'),
        ('Gradient Boosting','gradient_boosting','gb'),('Random Forest base','random_forest','rf')]:
        m=metrics.get(key)
        if not m:
            continue
        rows.append({'Configuración':label,'CV estratificada F1 (no temporal)':m.get('cv_f1_mean') if fold else None,
                     'Train F1':m.get('train_f1'),'Val F1':m.get('val_f1'),
                     'Test F1':m.get('f1_score'),'FPR test':m.get('fpr'),
                     'LODO F1':lodo.get(f'{fold}_f1_mean') if fold else None,
                     'LODO FPR':lodo.get(f'{fold}_fpr_mean') if fold else None,
                     'Latencia modelo (ms)':m.get('inference_ms_single_packet')})
    if 'rf_adaptive_f1_mean' in lodo:
        rows.append({'Configuración':'RF + umbral + consenso por archivo (histórico LODO)',
                     'CV estratificada F1 (no temporal)':None,'Train F1':None,'Val F1':None,
                     'Test F1':None,'FPR test':None,
                     'LODO F1':lodo['rf_adaptive_f1_mean'],'LODO FPR':lodo.get('rf_adaptive_fpr_mean'),
                     'Latencia modelo (ms)':None})
    return rows


def multiclass_tasks(m):
    # Old schema stored canonical scores under accuracy/f1_macro; raw scores were explicit.
    return [
        {'Tarea':'10 clases originales','Accuracy':m.get('raw_10_classes_accuracy'),
         'F1 macro':m.get('raw_10_classes_f1_macro')},
        {'Tarea':'9 firmas (TCP/UDP fusionados)','Accuracy':m.get('canonical_accuracy',m.get('accuracy')),
         'F1 macro':m.get('canonical_f1_macro',m.get('f1_macro'))},
    ]
