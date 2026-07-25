from datetime import datetime

timestamp_str = "2026-07-15T03:10:00Z"
timestamp_str = timestamp_str.replace("Z", "+00:00")  # make it timezone-explicit
parsed_time = datetime.fromisoformat(timestamp_str)
print(parsed_time)

time1 = datetime.fromisoformat("2026-07-15T03:10:00Z".replace("Z", "+00:00"))
time2 = datetime.fromisoformat("2026-07-15T03:13:00Z".replace("Z", "+00:00"))
diff = time2 - time1
print(diff)
print(diff.total_seconds())