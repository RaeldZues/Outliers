import pandas as pd
import glob2, numpy as np
import elasticsearch
import multiprocessing, os, json

pd.set_option('display.width', 500)
pd.set_option('max_colwidth', 50)
pd.set_option('display.max_rows', 80)
"""
This script sends my data from groups, group info, and User info to the elasticsearch index groupmembership
for processing
"""

def grouped(folders):
    groupmem = ''.join(glob2.glob(folders + "\\*groupmembership*"))
    groupmem = pd.read_csv(groupmem, names=['computername','groupname','name'], skiprows=1).fillna('NONE')
    groupmem['name'] = groupmem['name'].str.split(',')
    users = ''.join(glob2.glob(folders + "\\*userinfo*"))
    users = pd.read_csv(users, usecols=['Name'], names=['name'], skiprows=1).fillna('NONE')
    groupinfo = ''.join(glob2.glob(folders + "\\*groupinfo*"))
    groupinfo = pd.read_csv(groupinfo, names=['computername', 'groupname','localaccout','sid','sidtype','status'],
                            skiprows=1).fillna('NONE')
    groups = groupinfo.merge(groupmem, on=["groupname", 'computername'])
    groups = groups[['computername', 'groupname','sid','name','status']]

    #groups = groups.name.apply(lambda x: pd.Series(x)).stack().reset_index(level=1, drop=True).to_frame('name').join(groups[['computername','groupname','sid','status']], how='outer')
    x = [(idx, i) for idx, j in enumerate(groups['name']) for i in j]
    # Search the list for group names, if found resolve group
    # names to additional members of row where group was found
    for i, j in x:
        if j in set(groups.groupname):
            x.remove((i, j))
            for n in list(*list(groups['name'][groups.groupname == j])):
                x.append((i, n))

    # Create new DataFrame
    idx, names = zip(*x)
    z = pd.DataFrame(list(names), index=list(idx))

    # Join on the old one
    groups = groups.drop('name', axis=1).join(z)
    groups.columns = ['computername', 'groupname', 'sid', 'status', 'name']
    groups = groups[['computername','name','groupname','sid','status']]
   # This part turns my data into json, and outputs it to the elasticsearch instance.
    tmp = groups.to_json(orient='records')
    df_json=json.loads(tmp)
    for doc in df_json:
        try:
            es.index(index="groupmembership", doc_type="testing", body=doc)
        except elasticsearch.ElasticsearchException as es1:
            print(es1)
            print('error')



if __name__ == '__main__':
    path = glob2.glob(r'.\hostfolders\**\*')
    es = elasticsearch.Elasticsearch('my.ip.address:9200')
    # This prints what indices are currently in my elasticsearch instance
    indices = es.indices.get_alias().keys()
    print(indices)
    for folders in path:
        if os.path.isdir(folders):
            jobs = []
            p = multiprocessing.Process(grouped(folders))
            jobs.append(p)
            p.start()
