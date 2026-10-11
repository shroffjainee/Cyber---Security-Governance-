"""Evaluation metrics (computed per method, per simulation run).

Alert quality (asset-week level, onboarding week 0 excluded)
  precision, recall, F1, false alerts per 100 asset-weeks
Event level (harmful injected events)
  detection rate, mean detection delay (weeks), and the same for critical events
  (critical = harmful event on an asset with business value >= 6, i.e. important
  public-facing or regulated systems)
Prioritisation (each week with at least one harmful asset)
  NDCG@5 and Precision@5 of the method's ranking against GT priority
Persistence
  premature drop rate = share of still-harmful asset-weeks where the method
  dropped an alert it had raised the week before
"""
import numpy as np
import pandas as pd

from .simulate import business_value

K = 5


def _ndcg(rel_sorted_by_method, rel_ideal, k=K):
    def dcg(r):
        r = np.asarray(r[:k], dtype=float)
        return float(np.sum((2 ** r - 1) / np.log2(np.arange(2, len(r) + 2)))) if len(r) else 0.0
    ideal = dcg(sorted(rel_ideal, reverse=True))
    return dcg(rel_sorted_by_method) / ideal if ideal > 0 else np.nan


def evaluate_run(scores, events, gt, assets, seed=0):
    rng = np.random.default_rng(seed)
    val = {r["asset_id"]: business_value(r) for _, r in assets.iterrows()}
    out = []
    for m, s in scores.groupby("method"):
        d = s.merge(gt, on=["asset_id", "period"])
        e = d[d["period"] >= 1]
        tp = int(((e.alert == 1) & (e.gt_harmful == 1)).sum())
        fp = int(((e.alert == 1) & (e.gt_harmful == 0)).sum())
        fn = int(((e.alert == 0) & (e.gt_harmful == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else np.nan
        rec = tp / (tp + fn) if tp + fn else np.nan
        f1 = 2 * prec * rec / (prec + rec) if prec and rec and not np.isnan(prec) else np.nan
        fa100 = 100.0 * fp / len(e)

        alert_lookup = {(r.asset_id, r.period): r.alert for r in d.itertuples()}
        det, delay, det_c, delay_c = [], [], [], []
        for ev in events[events.harmful == 1].itertuples():
            hits = [t for t in range(ev.start, ev.end + 1) if alert_lookup.get((ev.asset_id, t), 0)]
            found = len(hits) > 0
            det.append(found)
            if found:
                delay.append(hits[0] - ev.start)
            if val[ev.asset_id] >= 6:
                det_c.append(found)
                if found:
                    delay_c.append(hits[0] - ev.start)

        ndcgs, p5s = [], []
        for t, w in e.groupby("period"):
            if (w.gt_priority > 0).sum() == 0:
                continue
            w = w.assign(tb=rng.random(len(w)))  # random tie-break: no luck from list order
            ranked = w.sort_values(["priority", "tb"], ascending=[False, False])
            ndcgs.append(_ndcg(ranked.gt_priority.tolist(), w.gt_priority.tolist()))
            relevant = set(w.sort_values("gt_priority", ascending=False).query("gt_priority > 0")
                           .asset_id.head(K))
            top = set(ranked.asset_id.head(K))
            p5s.append(len(top & relevant) / min(K, len(relevant)))

        d = d.sort_values(["asset_id", "period"])
        d["prev_alert"] = d.groupby("asset_id").alert.shift(1)
        d["prev_gt"] = d.groupby("asset_id").gt_harmful.shift(1)
        cont = d[(d.gt_harmful == 1) & (d.prev_gt == 1) & (d.prev_alert == 1)]
        drop = float((cont.alert == 0).mean()) if len(cont) else np.nan

        out.append(dict(method=m, precision=prec, recall=rec, f1=f1, false_alerts_per_100=fa100,
                        detection_rate=np.mean(det) if det else np.nan,
                        mean_delay=np.mean(delay) if delay else np.nan,
                        critical_detection_rate=np.mean(det_c) if det_c else np.nan,
                        critical_mean_delay=np.mean(delay_c) if delay_c else np.nan,
                        ndcg5=np.nanmean(ndcgs) if ndcgs else np.nan,
                        p5=np.mean(p5s) if p5s else np.nan,
                        premature_drop_rate=drop,
                        alerts=int(e.alert.sum())))
    return pd.DataFrame(out)
