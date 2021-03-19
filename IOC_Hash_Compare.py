import pandas as pd
import glob2
import multiprocessing
"""
This script compares an offline set of hashes from the NSRL database and an offline malware db that I have and compares them 
against collected host infomation. 
"""


def ioc_hash_compare(file, malware_db, nsrl_db):
    
    print('YOU HAVE STARTED YOUR OFFLINE MALWARE HASH COMPARISON')
    collected = pd.read_csv(file, names=['hash'], dtype='str')
    collected = collected.drop_duplicates(keep=False)
    full = [malware_db, collected]
    y = pd.concat(full, keys=['malware_db', 'collected'])
    y['Malware'] = y.duplicated('hash')
    y = y.ix['collected']
    y.to_csv(r'.\iocs\malware_matches\virus_%s.csv' % (file.split('\\')[-1].strip(".csv")))

    print('YOU HAVE STARTED YOUR OFFINE NSRL HASH COMPARISON')
    full_nsrl = [nsrl_db, collected]
    z = pd.concat(full_nsrl, keys=['nsrl_db', 'collected'])
    z = z.drop_duplicates(subset='hash', keep=False)
    print(z.head())
    z = z.ix['collected']
    z = z.sort_values(by='hash')
    z.to_csv(r'.\iocs\nsrl_nonmatches\nsrl_%s.csv' % (file.split('\\')[-1].strip(".csv")), index=False)


if __name__ == '__main__':
    sha1_path = glob2.glob(r'.\iocs\sorted\*sha1*.csv')
    malware_db = pd.read_csv(r'.\iocs\hash_dbs\sha1_malware.txt', names=['hash'])
    nsrl_db = pd.read_csv(r'.\iocs\hash_dbs\nsrlsha1.txt',names=['hash'])
    for file in sha1_path:
        jobs = []
        p = multiprocessing.Process(ioc_hash_compare(file, malware_db, nsrl_db))
        jobs.append(p)
        p.start()

