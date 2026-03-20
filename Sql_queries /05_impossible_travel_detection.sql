-- Impossible Travel Detection 
-- Detect users who appear to log in from two different countries within 4 hours 
WITH seq AS( 
SELECT
  ae.ip, 
  ae.user_id, 
  ae.event_id,
  ae.event_ts,
  ae.auth_result,
  ir.country,
  LAG(ir.country)OVER(
    PARTITION BY ae.user_id 
    ORDER BY ae.event_ts, ae.event_id
  ) AS prev_country,
  LAG(ae.event_ts)OVER(
    PARTITION BY ae.user_id 
    ORDER BY ae.event_ts, ae.event_id
  ) AS prev_ts
FROM auth_events ae 
JOIN ip_reputation ir 
  ON ae.ip = ir.ip
),

-- compute hours_since_prev
scored AS ( 
SELECT
  *, 
  (julianday(event_ts) - julianday(prev_ts)) * 24.0 AS hours_since_prev
FROM seq 
)
 
SELECT
	user_id, 
    ip,
    event_ts, 
    prev_ts,
    country, 
    prev_country,
    ROUND(hours_since_prev,2) AS hours_since_prev,
    auth_result
FROM scored
WHERE prev_country IS NOT NULL 
	AND country <> prev_country
    AND hours_since_prev <= 4
    AND auth_result = 'SUCCESS';
