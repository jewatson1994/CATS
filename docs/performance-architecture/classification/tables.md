# Second pass: per-scenario results (warm median ms / SQL ms / queries / bytes)

Before: `e20f906`. After: this pass. PostgreSQL 16, session time zone UTC, ANALYZEd databases, classification fixture applied.

## LARGE (1,001 services; service tabs on the 50,000-finding service)

| Request | Before: warm ms / SQL ms / queries / bytes | After: warm ms / SQL ms / queries / bytes | After: fresh-process first ms |
|---|---|---|---:|
| services: page | 78.2 / 16.8 / 18 / 14,340 | 72.3 / 13.5 / 18 / 14,340 | n/a |
| services: rows | 77.8 / 15.6 / 18 / 14,248 | 80.1 / 15.0 / 18 / 14,248 | n/a |
| cybersecurity: page | 66.7 / 12.1 / 14 / 70,695 | 71.4 / 11.2 / 14 / 70,695 | n/a |
| cybersecurity: data | 65.6 / 9.9 / 12 / 70,021 | 79.5 / 11.7 / 12 / 70,021 | n/a |
| service: overview | 191 / 152 / 37 / 9,324 | 146 / 101 / 39 / 9,324 | n/a |
| service: findings simplified | 407 / 380 / 24 / 21,051 | 171 / 139 / 24 / 21,051 | n/a |
| service: findings raw | 213 / 177 / 36 / 14,829 | 120 / 77.7 / 38 / 14,829 | n/a |
| service: findings search | 416 / 382 / 36 / 14,936 | 124 / 83.6 / 38 / 14,936 | n/a |
| findings: raw page 20 | 213 / 174 / 36 / 15,190 | 144 / 107 / 38 / 15,190 | n/a |
| findings: raw critical | 183 / 145 / 36 / 15,132 | 102 / 64.2 / 38 / 15,132 | n/a |
| findings: raw noncompliant | 117 / 83.4 / 30 / 19,785 | 99.1 / 66.1 / 30 / 19,785 | n/a |
| findings: raw exceptions | 3,360 / 569 / 35 / 16,746 | 93.5 / 53.2 / 38 / 16,746 | n/a |
| findings: raw resolved | 161 / 127 / 36 / 14,527 | 86.2 / 48.6 / 38 / 14,527 | n/a |
| findings: simplified search | 378 / 348 / 24 / 21,086 | 108 / 78.2 / 24 / 21,086 | n/a |
| findings: simplified critical | 125 / 97.3 / 24 / 14,518 | 78.3 / 49.4 / 24 / 14,518 | n/a |
| findings: simplified page 3 | 361 / 332 / 24 / 21,020 | 163 / 130 / 24 / 21,020 | n/a |
| findings: simplified noncompliant | 288 / 264 / 24 / 21,137 | 127 / 97.6 / 24 / 21,137 | n/a |
| findings: simplified members | 302 / 281 / 12 / 7,417 | 51.4 / 35.7 / 13 / 7,417 | n/a |
| service: poam | 27.5 / 8.9 / 23 / 1,181 | 27.0 / 8.9 / 24 / 1,181 | n/a |
| service: architecture | 37.5 / 10.1 / 25 / 70,795 | 44.0 / 10.9 / 26 / 70,795 | n/a |
| service: dependencies | 49.1 / 13.5 / 29 / 39,373 | 51.7 / 15.0 / 30 / 39,373 | n/a |
| service: validation | 28.8 / 9.3 / 25 / 3,914 | 31.2 / 10.2 / 26 / 3,914 | n/a |
| service: remediations | 37.1 / 12.0 / 31 / 2,868 | 38.2 / 11.9 / 32 / 2,868 | n/a |
| service: activity | 59.7 / 36.8 / 24 / 6,857 | 61.3 / 40.6 / 25 / 6,857 | n/a |
| service: artifacts | 28.1 / 9.5 / 24 / 6,836 | 31.4 / 10.4 / 25 / 6,836 | n/a |
| poll: remediation report | n/a | n/a | n/a |
| poll: deployment validation | n/a | n/a | n/a |
| poll: remediation status | n/a | n/a | n/a |
| poll: validation status | n/a | n/a | n/a |
| poll: dependencies status | 9.4 / 2.3 / 7 / 145 | 10.4 / 3.0 / 7 / 145 | n/a |

## MEDIUM (100 services; service tabs on a 10,000-finding service)

| Request | Before: warm ms / SQL ms / queries / bytes | After: warm ms / SQL ms / queries / bytes | After: fresh-process first ms |
|---|---|---|---:|
| services: page | 24.2 / 5.7 / 16 / 14,292 | 25.5 / 6.5 / 16 / 14,292 | n/a |
| services: rows | 22.0 / 5.8 / 16 / 14,200 | 24.6 / 6.5 / 16 / 14,200 | n/a |
| cybersecurity: page | 21.7 / 4.6 / 12 / 23,186 | 21.0 / 4.8 / 12 / 23,186 | n/a |
| cybersecurity: data | 16.4 / 3.4 / 10 / 22,511 | 18.3 / 3.9 / 10 / 22,512 | n/a |
| service: overview | 72.3 / 38.5 / 37 / 9,189 | 76.8 / 37.7 / 39 / 9,189 | n/a |
| service: findings simplified | 108 / 80.3 / 24 / 20,759 | 66.5 / 37.2 / 24 / 20,759 | n/a |
| service: findings raw | 74.8 / 42.1 / 36 / 14,717 | 72.8 / 34.7 / 38 / 14,717 | n/a |
| service: findings search | 133 / 98.4 / 36 / 14,812 | 70.2 / 34.3 / 38 / 14,812 | n/a |
| findings: raw page 20 | 78.5 / 42.9 / 36 / 14,708 | 69.2 / 33.1 / 38 / 14,708 | n/a |
| findings: raw critical | 78.5 / 40.0 / 36 / 14,894 | 64.1 / 29.5 / 38 / 14,894 | n/a |
| findings: raw noncompliant | 67.3 / 34.8 / 30 / 19,517 | 71.1 / 34.8 / 30 / 19,517 | n/a |
| findings: raw exceptions | 702 / 132 / 35 / 16,389 | 64.9 / 27.9 / 38 / 16,389 | n/a |
| findings: raw resolved | 69.8 / 34.2 / 36 / 14,224 | 62.2 / 25.7 / 38 / 14,224 | n/a |
| findings: simplified search | 166 / 136 / 24 / 20,777 | 51.7 / 25.2 / 24 / 20,777 | n/a |
| findings: simplified critical | 62.1 / 32.9 / 24 / 14,312 | 47.1 / 20.9 / 24 / 14,312 | n/a |
| findings: simplified page 3 | 114 / 86.3 / 24 / 20,717 | 62.6 / 35.8 / 24 / 20,717 | n/a |
| findings: simplified noncompliant | 107 / 79.2 / 24 / 20,831 | 58.6 / 32.0 / 24 / 20,831 | n/a |
| findings: simplified members | 86.9 / 64.0 / 12 / 3,741 | 25.2 / 10.7 / 13 / 3,741 | n/a |
| service: poam | 29.2 / 10.0 / 23 / 1,175 | 29.5 / 10.8 / 24 / 1,175 | n/a |
| service: architecture | 43.6 / 12.9 / 25 / 70,762 | 44.6 / 13.3 / 26 / 70,762 | n/a |
| service: dependencies | 52.1 / 17.2 / 29 / 39,279 | 45.5 / 15.6 / 30 / 39,279 | n/a |
| service: validation | 37.6 / 14.3 / 25 / 31,556 | 37.4 / 12.3 / 26 / 31,556 | n/a |
| service: remediations | 41.8 / 13.6 / 31 / 3,515 | 40.8 / 14.2 / 32 / 3,515 | n/a |
| service: activity | 37.4 / 14.7 / 24 / 6,970 | 36.3 / 14.9 / 25 / 6,970 | n/a |
| service: artifacts | 31.7 / 11.3 / 24 / 6,746 | 32.6 / 12.0 / 25 / 6,746 | n/a |
| poll: remediation report | 43.8 / 9.8 / 17 / 280,860 | 41.5 / 9.3 / 17 / 280,860 | n/a |
| poll: deployment validation | 151 / 16.4 / 7 / 96,934 | 153 / 15.2 / 7 / 96,934 | n/a |
| poll: remediation status | 10.0 / 2.5 / 7 / 1,908 | 10.8 / 2.7 / 7 / 1,908 | n/a |
| poll: validation status | 8.5 / 2.2 / 6 / 633 | 9.1 / 2.1 / 6 / 633 | n/a |
| poll: dependencies status | 10.0 / 2.3 / 7 / 142 | 10.8 / 2.7 / 7 / 142 | n/a |
