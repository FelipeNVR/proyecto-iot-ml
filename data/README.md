# Detection of IoT Botnet Attacks 
## N-BaIoT dataset

## Abstract:

This dataset addresses the lack of public botnet datasets, especially for the IoT. It suggests *real* traffic data, gathered from 9 commercial IoT devices authentically infected by Mirai and BASHLITE.

## Dataset Characteristics:  

* Multivariate, Sequential
* Number of Instances: 7062606
* Area: Computer Attribute Characteristics:
* Real Number of Attributes: 115
* Date Donated: 2018-03-19
* Associated Tasks: Classification, Clustering
* Missing Values: N/A


## Source:

#### URL:
http://archive.ics.uci.edu/ml/datasets/detection_of_IoT_botnet_attacks_N_BaIoT

#### Creators:
* Yair Meidan
* Michael Bohadana
* Yael Mathov
* Yisroel Mirsky
* Dominik Breitenbacher
* Asaf Shabtai
* Yuval Elovici


### Dataset Information:

##### Attribute being predicted:
* Originally we aimed at distinguishing between benign and Malicious traffic data by means of anomaly detection techniques.
* However, as the malicious data can be divided into 10 attacks carried by 2 botnets, the dataset can also be used for multi-class classification: 10 classes of attacks, plus 1 class of 'benign'.

##### The study's results:
* For each of the 9 IoT devices we trained and optimized a deep autoencoder on 2/3 of its benign data (i.e., the training set of each device). This was done to capture normal network traffic patterns.
* The test data of each device comprised of the remaining 1/3 of benign data plus all the malicious data. On each test set we applied the respective trained (deep) autoencoder as an anomaly detector. The detection of anomalies (i.e., the cyberattacks launched from each of the above IoT devices) concluded with 100% TPR.


### Attribute Information:

The following describes each of the features headers:
##### Stream aggregation:
__H:__ Stats summarizing the recent traffic from this packet's host (IP)<br>
__HH:__ Stats summarizing the recent traffic going from this packet's host (IP) to the packet's destination host.<br>
__HpHp:__ Stats summarizing the recent traffic going from this packet's host+port (IP) to the packet's destination host+port. Example 192.168.4.2:1242 -> 192.168.4.12:80<br>
__HH_jit:__ Stats summarizing the jitter of the traffic going from this packet's host (IP) to the packet's destination host.

##### Time-frame (The decay factor Lambda used in the damped window):
How much recent history of the stream is capture in these statistics
L5, L3, L1, ...

##### The statistics extracted from the packet stream:
__weight:__ The weight of the stream (can be viewed as the number of items observed in recent history)<br>
__mean:__ ...<br>
__std:__ ...<br>
__radius:__ The root squared sum of the two streams' variances<br>
__magnitude:__ The root squared sum of the two streams' means<br>
__cov:__ an approximated covariance between two streams<br>
__pcc:__ an approximated covariance between two streams<br>

### Citation Policy

http://archive.ics.uci.edu/ml/citation_policy.html

```
@misc{Dua:2019 ,
author = "Dua, Dheeru and Graff, Casey",
year = "2017",
title = "{UCI} Machine Learning Repository",
url = "http://archive.ics.uci.edu/ml",
institution = "University of California, Irvine, School of Information and Computer Sciences" }
```

### Relevant Papers:

Reference to the article where the feature extractor (from *.pcap to *.csv) was described:<br>

__Y. Mirsky, T. Doitshman, Y. Elovici & A. Shabtai__, 'Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection', in Network and Distributed System Security (NDSS) Symposium, San Diego (2018), CA, USA.



### Citation Request:

Reference to the article where the dataset was initially described and used:<br>
__Y. Meidan, M. Bohadana, Y. Mathov, Y. Mirsky, D. Breitenbacher,__ A. Shabtai, and Y. Elovici 'N-BaIoT: Network-based Detection of IoT Botnet Attacks Using Deep Autoencoders', IEEE Pervasive Computing, Special Issue - Securing the IoT (July/Sep 2018).