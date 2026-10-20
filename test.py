# arr = [1,2,3,4]

# a = [x *2 for x in arr]
# b = [x for x in arr if x > 1]
# print(a)
# print(b)

# event = {
#   "EventId" : 1,
#   "Channel" : "Microsoft",
#   "EventData" : {"Images" : "Bang"},
# }

# a = event["EventId"]
# b = event.get("Channel", "unknown")
# c = event.get("EventData",{}).get("Images")
# print(a)
# print(b)
# print(c)

# import json
# from pathlib import Path
# from collections import Counter

# events,bad = [] , 0

# with Path("sample_events.jsonl").open(encoding="utf-8") as f :
#   for line_no, line in enumerate(f,start=1) :
#     line = line.strip()
#     if not line :
#       continue
#     try :
#       events.append(json.loads(line))
#     except :
#       bad +=1
#       print(f"dòng {line_no} lỗi, bỏ qua")

# print(len(events))
# print(type(events))
# print(type(events[0]))
# print(events[0])

# counts = {}
# for e in events :
#   eid = e["EventID"]
#   counts[eid] = counts.get(eid, 0) + 1

# Counter(e["EventID"] for e in events).most_common(5)

# a = Counter((e["Channel"], e["EventID"]) for e in events)
# print(a)

# from pathlib import PureWindowsPath
# from datetime import datetime

# # PureWindowsPath(r"C:\Windows\System32\cmd.exe").name.lower()

# names = [PureWindowsPath(e["Image"]).name.lower() for e in events if e.get("Image") ]

# # ts = datetime.strptime("2019-02-13 15:14:52.409735", "%Y-%m-%d %H:%M:%S.%f")
# # print(ts.hour)

# def parse_ts(s):
#   fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in s else "%Y-%m-%d %H:%M:%S"
#   return datetime.strptime(s, fmt)

# Counter(parse_ts(e["SystemTime"]).hour for e in events).most_common(1)

# Ngày 3 :NumPy
import numpy as np
# ids = np.array([1, 3, 1,4,5,6,7,1,3 ])
# ids1 = np.array([[1,2],["2","3"],[3,4]])

# vals,cnt = np.unique(ids, return_counts=True)
# print(vals)
# print(cnt)

a = np.array([1.0, np.nan, 3.0])

print(a.mean())
