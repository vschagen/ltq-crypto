Refactored Lantiq Data Encryption Unit driver

Initial version:

Performance compared to orginal driver:

ltq-deu driver:

```
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
aes-128-ecb       1124.33k     4067.84k    12076.03k    23655.77k    32180.91k    33325.06k
aes-256-ecb       1136.80k     4035.10k    11750.49k    22192.81k    29106.18k    29529.43k
aes-128-cbc       1040.14k     3781.95k    11425.37k    23005.87k    32230.06k    33161.22k
aes-256-cbc       1024.98k     3736.73k    11010.22k    21618.35k    28893.18k    29573.12k
aes-128-ctr       1505.14k     3649.19k    11163.82k    23202.47k    32325.63k    33303.21k
aes-256-ctr       1520.47k     3568.73k    10785.54k    21271.89k    28940.50k    29534.89k

```

```
# Tests are approximate using memory only (no storage IO).
# Algorithm |       Key |      Encryption |      Decryption
    aes-ecb        128b        26.0 MiB/s        26.0 MiB/s
    aes-ecb        256b        23.8 MiB/s        23.8 MiB/s
    aes-cbc        128b        25.9 MiB/s        25.9 MiB/s
    aes-cbc        256b        24.1 MiB/s        24.1 MiB/s
    aes-cfb        128b        25.7 MiB/s        25.8 MiB/s
    aes-cfb        256b        23.3 MiB/s        23.4 MiB/s
    aes-ofb        128b        26.0 MiB/s        26.0 MiB/s
    aes-ofb        256b        23.6 MiB/s        23.6 MiB/s
    aes-ctr        128b        25.4 MiB/s        25.6 MiB/s
    aes-ctr        256b        23.5 MiB/s        23.5 MiB/s
    aes-xts        256b        18.6 MiB/s        19.9 MiB/s
    aes-xts        512b        17.5 MiB/s        18.6 MiB/s

```
ltq-crypto driver:

```
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
aes-128-ecb       1141.35k     4114.35k    12609.19k    25359.36k    34796.89k    35804.50k
aes-256-ecb       1135.17k     4080.04k    12595.20k    25401.02k    34796.89k    35777.19k
aes-128-cbc        934.34k     3475.63k    10956.54k    23702.53k    34261.67k    35302.06k
aes-256-cbc        946.29k     3469.76k    11052.97k    23671.81k    34299.90k    35520.51k
aes-128-ctr       1419.60k     3759.06k    11684.22k    24748.03k    34455.55k    35454.98k
aes-256-ctr       1423.99k     3803.43k    11703.30k    24631.14k    34428.25k    35438.59k
```

```
# Tests are approximate using memory only (no storage IO).
# Algorithm |       Key |      Encryption |      Decryption
    aes-ecb        128b        27.7 MiB/s        27.8 MiB/s
    aes-ecb        256b        27.7 MiB/s        27.8 MiB/s
    aes-cbc        128b        27.5 MiB/s        27.5 MiB/s
    aes-cbc        256b        27.4 MiB/s        27.5 MiB/s
    aes-cfb        128b        27.1 MiB/s        27.2 MiB/s
    aes-cfb        256b        27.2 MiB/s        27.2 MiB/s
    aes-ofb        128b        27.0 MiB/s        27.0 MiB/s
    aes-ofb        256b        27.3 MiB/s        27.3 MiB/s
    aes-ctr        128b        27.2 MiB/s        27.2 MiB/s
    aes-ctr        256b        27.3 MiB/s        27.4 MiB/s
    aes-xts        256b        21.8 MiB/s        21.2 MiB/s
    aes-xts        512b        21.8 MiB/s        21.3 MiB/s

```
