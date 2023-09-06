
The files are named with triples of numbers, where the first two indicate recommended upper bounds for the sender's and receiver's set sizes, respectively, and the third (optional) number indicates that the parameters are meant for use in labeled mode and denote the label byte size. The file names end with an optional specifier -com or -cmp, indicating whether the parameters are optimized to minimize communication or computation cost. (https://github.com/microsoft/APSI/tree/main)


Parameters were selected according to the following criteria:

1) Ensuring fairness with the SPSI setting during the execution of a Private Membership Test (PMT) where the client holds a singleton set.
2) For certain existing parameters such as 1M-512-cmp and 1M-512-com, where the server size was 1M, the minimal client size was chosen from the available options to optimize communication OR computational complexity.
3) The maximum possible server size was selected for APSI (256M).

