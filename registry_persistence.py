import pandas as pd
import glob2
import multiprocessing

pd.set_option('display.width', 500)
pd.set_option('max_colwidth', 200)
pd.set_option('display.max_rows', 80)

def registry_persistence(file):
    reg_paths = pd.read_csv(r'mypathto\autoruns.csv', names=['Path'],index_col=None)
    df = pd.read_csv(file)
    pat = reg_paths.Path.apply(re.escape).str.replace(r'\\\*', r'[^\\\]*').str.cat(sep='|')
    autoruns = df[df.Path.str.contains(pat)]
    autoruns.to_csv(r".\\registry_keys\persistence\\autoruns_%s.csv" % (str(file).split('\\')[-1].strip('.csv')))

    """
    This section gets all the other requirements out for my Least Frequency of Occurance
    Still working on refining this piece as it provided too many false positives.
    """
    services = df[df.Path.str.contains(r"services", case=False)]
    services.to_csv(r'.\registry_keys\Services\services_%s.csv' % (str(file).split('\\')[-1].strip('.csv')))
    software = df[df.Path.str.contains(r"installed", case=False)]
    software.to_csv(r'.\Registry_Keys\Software_Installed\software_%s.csv' % (str(file).split('\\')[-1].strip('.csv')))

if __name__ == '__main__':
    by_host_converted = glob2.glob(r'.\registry_keys\by host converted\*.csv')
    for file in by_host_converted:
        jobs = []
        p = multiprocessing.Process(registry_persistence(file))
        jobs.append(p)
        p.start()
