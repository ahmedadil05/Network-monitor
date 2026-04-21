# KDD Cup 1999 Dataset

## Download Instructions

The KDD Cup 1999 dataset can be downloaded from the UCI Machine Learning Repository:

**Direct Link:**
```bash
curl -L "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data" -o KDDTrain+.txt
```

**Or using wget:**
```bash
wget http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data -O KDDTrain+.txt
```

**File Size:** ~414 MB (compressed: ~81 MB)
**Records:** ~5 million network records

## Features

The dataset contains network intrusion detection data with the following fields:
- duration, protocol_type, service, flag, src_bytes, dst_bytes
- land, wrong_fragment, urgent, hot, num_failed_logins
- logged_in, num_compromised, root_shell, su_attempted
- num_root, num_file_creations, num_shells, num_access_files
- num_outbound_cmds, is_host_login, is_guest_login
- count, srv_count, serror_rate, srv_serror_rate
- rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate
- srv_diff_host_rate, dst_host_count, dst_host_srv_count
- dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate
- dst_host_srv_diff_host_rate, attack_label

## Usage

Once downloaded, place the file in this directory as `KDDTrain+.txt` and it will be automatically loaded by the application.

## Alternative: Small Sample

For testing purposes, you can use the 10% subset:
```bash
curl -L "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz" | gunzip > KDDTrain+_10percent.txt
```
