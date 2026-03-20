-- Latest Login Per User
/* Which login event was the most recent for each user, 
	including timestamp, result, IP and application used?
*/
WITH ranked AS ( 
SELECT
  u.user_id, 
  u.full_name, 
  u.dept, 
  u.role, 
  ae.event_ts,
  ae.auth_result,
  ae.ip, 
  ae.app,
  ROW_NUMBER()OVER(
    PARTITION BY u.user_id 
    ORDER BY ae.event_ts DESC, ae.event_id DESC
  ) AS rn
FROM users u
INNER JOIN auth_events ae
  ON u.user_id = ae.user_id
)

SELECT * 
FROM ranked 
WHERE rn = 1;
