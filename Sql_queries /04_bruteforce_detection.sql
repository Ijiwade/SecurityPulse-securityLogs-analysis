-- Brute Force Detection 
-- Detect 2 failed followed by a success within 5 minutes for the same user 

WITH seq AS ( 
SELECT
  ae.event_id,
  ae.user_id,
  ae.event_ts,
  ae.auth_result, 
  ae.ip,
  ae.app,
  LAG(ae.auth_result)OVER(
    PARTITION BY ae.user_id 
    ORDER BY ae.event_ts, ae.event_id
  ) AS prev_result,
  LAG(ae.auth_result, 2)OVER(
    PARTITION BY ae.user_id 
    ORDER BY ae.event_ts, ae.event_id
  ) AS prev2_result,
  LAG(ae.event_ts)OVER(
    PARTITION BY ae.user_id
    ORDER BY ae.event_ts, ae.event_id
  ) AS prev_ts, 
  LAG(ae.event_ts, 2)OVER(
    PARTITION BY ae.user_id
    ORDER BY ae.event_ts, ae.event_id
  ) AS prev2_ts
FROM auth_events ae
), 

scored AS ( 
SELECT
  *,
  (julianday(event_ts) - julianday(prev_ts)) * 1440.0 AS min_btw_cur_prev,
  (julianday(prev_ts) - julianday(prev2_ts)) * 1440.0 AS min_btw_prev_prev2
FROM seq
)

SELECT
	event_id,
    user_id, 
    auth_result,
    ip, 
    app, 
    prev_ts, 
    prev2_ts, 
    min_btw_cur_prev, 
    min_btw_prev_prev2
FROM scored
WHERE auth_result = 'SUCCESS'
	AND prev_result = 'FAIL'
    AND prev2_result = 'FAIL'
    AND min_btw_cur_prev <= 5
    AND min_btw_prev_prev2 <= 5
ORDER BY auth_result;
