import pandas as pd
import glob2, multiprocessing, os
import json, pyes
from elasticsearch import Elasticsearch

pd.set_option('display.width', 500)
pd.set_option('max_colwidth', 30)
pd.set_option('display.max_rows', 50)

"""
This script takes and accepts sha1 hashes csv, dlls listing csv, process listing csv and combines them to find
correlations. This outputs to elasticsearch for kibana viewing. Can be manipulated to fit your needs.
"""


def convert_processes(folders):
    sha1 = ''.join(glob2.glob(folders + "\\*sha1_hashes*"))
    sha1 = pd.read_csv(sha1, encoding='UTF-16', delimiter="\t",names=['HashType','SHA1', 'HostName', 'ModulePath']).fillna('NONE')
    dlls = ''.join(glob2.glob(folders + "\\*dllinfo*"))
    dlls = pd.read_csv(dlls, names=['ProcessName', 'ProcessId', 'ProcessPath', 'ModuleName','ModulePath']).fillna('NONE')
    processes = ''.join(glob2.glob(folders + "\\*process*"))
    processes = pd.read_csv(processes,  names=['HostName', 'ProcessName','ProcessPath', 'ProcessId','ParentProcessId','ProcessOwner']).fillna('NONE')
    processes['ParentProcessName'] = processes.ParentProcessId.map(processes.set_index('ProcessId').ProcessName)
    combined = processes.merge(dlls, on="ProcessId", how='left').merge(sha1, on='ModulePath', how='left')
    combined = combined[['HostName_x','ProcessName_x', 'ProcessId','ProcessPath_x','ProcessOwner','ParentProcessName','ParentProcessId','ModuleName','ModulePath','SHA1']]
    combined = combined.sort_values(by='ProcessName_x')
    combined.columns =['HostName', 'ProcessName', 'ProcessId', 'ProcessPath','ProcessOwner','ParentProcessName','ParentProcessId','ModuleName', 'ModulePath','SHA1']
    combined = combined.fillna('NONE')
    print(combined)
"""
    # pushes my dataframe to elasticsearch (need to configure on a by df type basis)
    tmp = combined.to_json(orient='records')
    df_json=json.loads(tmp)
    for doc in df_json:
        try:
            es.index(index="logstash", doc_type="testing", body=doc)
        except:
            pass
"""

if __name__ == '__main__':
    path = glob2.glob(r'hostfolders\**\*')
    #es = Elasticsearch('http://ipaddresstoyourelasticsearch:9200')
    #indices = es.indices.get_alias().keys()
    jobs = []
    with multiprocessing.Pool(processes=20) as pool:
        for folders in path:
            if os.path.isdir(folders):
                try:
                    p = multiprocessing.Process(pool.apply_async(convert_processes(folders))
                    jobs.append(p)
                    p.start()
                except:
                    pass


