-- First Device Per User 
-- What device was first used by each user? 
WITH ranked AS ( 
SELECT
  u.user_id, 
  u.full_name, 
  d.device_id, 
  d.device_type, 
  d.os, 
  d.is_managed, 
  d.first_seen_ts,
  ROW_NUMBER()OVER(
    PARTITION BY u.user_id 
    ORDER BY d.first_seen_ts
  ) AS rn
FROM users u 
JOIN devices d 
  ON u.user_id = d.user_id
)

SELECT * 
FROM ranked
WHERE rn = 1;
